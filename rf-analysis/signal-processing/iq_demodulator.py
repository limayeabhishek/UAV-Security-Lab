#!/usr/bin/env python3
"""
SECUREDRONE — Offline RF Signal Processing & 2-GFSK Demodulator
Stage 05 | RF & Wireless Security Research

Synthesizes and processes raw complex IQ telemetry signals (simulating 915 MHz SiK / HopeRF transceivers).
Implements FM quadrature discrimination, Gaussian low-pass filtering, symbol clock recovery,
sync word correlation, and CRC-16 integrity validation.
"""

import json
import os
import struct
from typing import Any, Dict, Tuple
import numpy as np
import scipy.signal as signal
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


class GFSKSignalPipeline:
    """End-to-end signal generator and demodulator for drone telemetry links."""

    def __init__(self, sample_rate: int = 1_000_000, symbol_rate: int = 50_000, f_dev: float = 25_000):
        self.sample_rate = sample_rate
        self.symbol_rate = symbol_rate
        self.f_dev = f_dev
        self.samples_per_symbol = int(sample_rate // symbol_rate)

    @staticmethod
    def crc16_ccitt(data: bytes) -> int:
        crc = 0xFFFF
        for b in data:
            crc ^= (b << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return crc

    def synthesize_telemetry_frame(self, payload_text: str = "SECUREDRONE_TELEMETRY_PKT_01") -> Tuple[bytes, np.ndarray]:
        """
        Creates a link-layer frame:
        [Preamble: 0xAAAAAAAA][Sync: 0x2DD4][Len: 1B][Payload][CRC: 2B]
        Modulates into 2-GFSK IQ samples.
        """
        preamble = b"\xAA\xAA\xAA\xAA"
        sync_word = b"\x2D\xD4"
        payload = payload_text.encode("utf-8")
        length_byte = struct.pack("B", len(payload))
        frame_without_crc = length_byte + payload
        crc_val = self.crc16_ccitt(frame_without_crc)
        crc_bytes = struct.pack(">H", crc_val)
        full_packet = preamble + sync_word + frame_without_crc + crc_bytes

        # Convert packet bytes to bitstream
        bits = []
        for byte in full_packet:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        bits = np.array(bits, dtype=float)

        # Map bits (0, 1) -> NRZ (-1, +1)
        nrz = 2.0 * bits - 1.0

        # Upsample
        upsampled = np.zeros(len(nrz) * self.samples_per_symbol)
        upsampled[::self.samples_per_symbol] = nrz

        # Gaussian Pulse Shaping Filter (BT = 0.5)
        bt = 0.5
        t = np.arange(-2 * self.samples_per_symbol, 2 * self.samples_per_symbol + 1) / self.samples_per_symbol
        alpha = np.sqrt(2 * np.log(2)) / bt
        gauss_filter = (np.sqrt(np.pi) / alpha) * np.exp(-(np.pi * t / alpha) ** 2)
        gauss_filter /= np.sum(gauss_filter)

        freq_pulse = np.convolve(upsampled, gauss_filter, mode="same")
        # Frequency deviation scaling
        freq_dev_rad = 2 * np.pi * self.f_dev * (freq_pulse / np.max(np.abs(freq_pulse)))

        # Integrate frequency to get phase
        phase = np.cumsum(freq_dev_rad) / self.sample_rate

        # Generate complex IQ
        iq_clean = np.exp(1j * phase)

        # Add realistic additive white Gaussian noise (AWGN) (SNR ~ 22 dB)
        noise_power = 0.02
        noise = (np.random.normal(0, np.sqrt(noise_power / 2), len(iq_clean)) +
                 1j * np.random.normal(0, np.sqrt(noise_power / 2), len(iq_clean)))
        iq_noisy = (iq_clean + noise).astype(np.complex64)

        return full_packet, iq_noisy

    def demodulate(self, iq_samples: np.ndarray) -> Dict[str, Any]:
        """
        Demodulates 2-GFSK IQ samples into recovered bits and validates packet integrity.
        """
        # 1. Quadrature Demodulation: instantaneous frequency = d(phase)/dt
        phase_diff = iq_samples[1:] * np.conj(iq_samples[:-1])
        demod_freq = np.angle(phase_diff)

        # 2. Moving Average / Low-pass filtering
        filter_len = self.samples_per_symbol // 2
        kernel = np.ones(filter_len) / filter_len
        filtered_baseband = np.convolve(demod_freq, kernel, mode="same")

        # 3. Multi-phase Symbol Timing Recovery
        sync_bits = [0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0]
        sync_len = len(sync_bits)

        best_result = None

        # Sweep candidate sample clock phases
        for phase_offset in range(self.samples_per_symbol):
            sample_indices = np.arange(phase_offset, len(filtered_baseband), self.samples_per_symbol)
            sampled_symbols = filtered_baseband[sample_indices]
            recovered_bits = (sampled_symbols > 0).astype(int)

            # Search for sync word
            for i in range(len(recovered_bits) - sync_len - 24):
                if np.array_equal(recovered_bits[i:i + sync_len], sync_bits):
                    data_bits = recovered_bits[i + sync_len:]
                    
                    # Convert bits to bytes
                    recovered_bytes = bytearray()
                    for b_idx in range(0, (len(data_bits) // 8) * 8, 8):
                        byte_val = 0
                        for bit_pos in range(8):
                            byte_val = (byte_val << 1) | int(data_bits[b_idx + bit_pos])
                        recovered_bytes.append(byte_val)

                    if len(recovered_bytes) >= 3:
                        payload_len = recovered_bytes[0]
                        total_expected = 1 + payload_len + 2
                        if len(recovered_bytes) >= total_expected:
                            packet_body = bytes(recovered_bytes[:total_expected])
                            length_and_payload = packet_body[:-2]
                            received_crc = struct.unpack(">H", packet_body[-2:])[0]
                            calculated_crc = self.crc16_ccitt(length_and_payload)

                            crc_valid = (received_crc == calculated_crc)
                            payload_text = length_and_payload[1:].decode("utf-8", errors="replace")

                            return {
                                "status": "PASS" if crc_valid else "FAIL",
                                "sync_acquired": True,
                                "optimal_clock_phase": phase_offset,
                                "sync_bit_index": i,
                                "recovered_payload_len": payload_len,
                                "recovered_payload_ascii": payload_text,
                                "received_crc": hex(received_crc),
                                "calculated_crc": hex(calculated_crc),
                                "crc_valid": crc_valid,
                                "demod_metrics": {
                                    "total_iq_samples": len(iq_samples),
                                    "sample_rate_hz": self.sample_rate,
                                    "symbol_rate_baud": self.symbol_rate,
                                    "samples_per_symbol": self.samples_per_symbol,
                                }
                            }

        return {"status": "FAIL", "reason": "Sync word 0x2DD4 not acquired across sample clock phases"}

    def generate_visual_artifacts(self, iq_samples: np.ndarray, output_plot_path: str):
        """Generates power spectrum (PSD) and demodulated baseband eye diagram."""
        fig, axes = plt.subplots(2, 1, figsize=(10, 8))

        # 1. Power Spectral Density (PSD)
        fft_len = 1024
        psd, freqs = plt.psd(iq_samples, NFFT=fft_len, Fs=self.sample_rate / 1000, sides="twosided")
        axes[0].clear()
        freqs_khz = np.fft.fftshift(np.fft.fftfreq(fft_len, d=1.0 / (self.sample_rate / 1000)))
        spec = np.fft.fftshift(np.abs(np.fft.fft(iq_samples[:fft_len])) ** 2)
        spec_db = 10 * np.log10(spec + 1e-12)
        axes[0].plot(freqs_khz, spec_db, color="#1f77b4", linewidth=1.2)
        axes[0].set_title("SECUREDRONE — 2-GFSK Telemetry Power Spectral Density (PSD)", fontsize=12, fontweight="bold")
        axes[0].set_xlabel("Frequency Offset (kHz)")
        axes[0].set_ylabel("Power Spectral Density (dB/Hz)")
        axes[0].grid(True, linestyle="--", alpha=0.6)

        # 2. Time-Domain Baseband Discriminator Output
        phase_diff = iq_samples[1:2000] * np.conj(iq_samples[:1999])
        demod_freq = np.angle(phase_diff)
        axes[1].plot(demod_freq[:800], color="#d62728", linewidth=1.0)
        axes[1].set_title("Demodulated Baseband Instantaneous Frequency (FM Discriminator)", fontsize=12, fontweight="bold")
        axes[1].set_xlabel("Sample Index")
        axes[1].set_ylabel("Normalized Frequency (rad/sample)")
        axes[1].grid(True, linestyle="--", alpha=0.6)

        plt.tight_layout()
        os.makedirs(os.path.dirname(output_plot_path) or ".", exist_ok=True)
        plt.savefig(output_plot_path, dpi=150)
        plt.close()
        print(f"[+] Signal analysis visualization saved to: {output_plot_path}")


def main():
    pipeline = GFSKSignalPipeline(sample_rate=1_000_000, symbol_rate=50_000, f_dev=25_000)
    
    iq_path = "rf-analysis/datasets/telemetry_sik_915mhz.iq"
    meta_path = "rf-analysis/datasets/telemetry_sik_915mhz.json"
    plot_path = "evidence/rf_demodulation_plot.png"
    
    print("[*] Synthesizing 2-GFSK telemetry frame with Link-Layer framing...")
    raw_packet, iq_samples = pipeline.synthesize_telemetry_frame("SECUREDRONE_MAVLINK_MISSION_WAYPOINT_LAT37_LON122")

    # Save raw IQ dataset
    os.makedirs(os.path.dirname(iq_path) or ".", exist_ok=True)
    iq_samples.tofile(iq_path)
    
    metadata = {
        "dataset_name": "telemetry_sik_915mhz",
        "modulation": "2-GFSK",
        "sample_rate_sps": 1_000_000,
        "symbol_rate_baud": 50_000,
        "frequency_deviation_hz": 25_000,
        "sample_format": "complex64 (float32 I, float32 Q)",
        "file_size_bytes": os.path.getsize(iq_path),
        "link_layer_protocol": "SiK / HopeRF Compatible",
        "preamble_hex": "AAAAAAAA",
        "sync_word_hex": "2DD4",
        "crc_algorithm": "CRC-16-CCITT"
    }
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Offline IQ dataset saved: {iq_path} ({metadata['file_size_bytes']} bytes)")
    print(f"[+] Dataset metadata recorded: {meta_path}")

    # Demodulate from file
    print("[*] Running quadrature demodulation and frame recovery...")
    loaded_iq = np.fromfile(iq_path, dtype=np.complex64)
    demod_result = pipeline.demodulate(loaded_iq)
    print(json.dumps(demod_result, indent=2))

    # Generate plots
    pipeline.generate_visual_artifacts(loaded_iq, plot_path)


if __name__ == "__main__":
    main()
