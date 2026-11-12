#!/usr/bin/env python3
"""
SECUREDRONE — Modular MAVLink Protocol Analyzer
Stage 01/02 | Module 1: Binary Protocol Analyzer & PCAP Dissector

Parses raw MAVLink v1 (0xFE) and MAVLink v2 (0xFD) frames directly from byte
buffers, network sockets, or PCAP capture files. Validates frame integrity,
extracts system identities, maps sequence continuity, and evaluates cryptographic
signing flags.
"""

import json
import struct
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


# Standard MAVLink Message IDs
MSG_ID_MAP = {
    0: "HEARTBEAT",
    1: "SYS_STATUS",
    2: "SYSTEM_TIME",
    4: "PING",
    20: "PARAM_REQUEST_READ",
    21: "PARAM_REQUEST_LIST",
    22: "PARAM_VALUE",
    23: "PARAM_SET",
    24: "GPS_RAW_INT",
    30: "ATTITUDE",
    31: "ATTITUDE_QUATERNION",
    32: "LOCAL_POSITION_NED",
    33: "GLOBAL_POSITION_INT",
    42: "MISSION_CURRENT",
    43: "MISSION_REQUEST_LIST",
    44: "MISSION_COUNT",
    45: "MISSION_ITEM",
    46: "MISSION_REQUEST",
    47: "MISSION_SET_CURRENT",
    48: "MISSION_ACK",
    76: "COMMAND_LONG",
    77: "COMMAND_ACK",
    83: "ATTITUDE_TARGET",
    84: "POSITION_TARGET_LOCAL_NED",
    87: "POSITION_TARGET_GLOBAL_INT",
    147: "BATTERY_STATUS",
    245: "EXTENDED_SYS_STATE",
    253: "STATUSTEXT",
}


@dataclass
class MAVLinkFrame:
    version: int                 # 1 or 2
    magic: int                   # 0xFE or 0xFD
    payload_len: int
    incompat_flags: int          # v2 only (bit 0 = signed)
    compat_flags: int            # v2 only
    seq: int
    sys_id: int
    comp_id: int
    msg_id: int
    msg_name: str
    payload: bytes
    crc: int
    is_signed: bool
    signature_data: Optional[Dict[str, Any]] = None
    raw_frame: bytes = b""


class MAVLinkParser:
    """Zero-dependency low-level wire parser for MAVLink v1 and v2 frames."""

    @staticmethod
    def parse_frame(buffer: bytes) -> Optional[Tuple[MAVLinkFrame, int]]:
        """
        Parses a single MAVLink frame from the start of buffer.
        Returns (MAVLinkFrame, consumed_bytes) or None if incomplete/invalid.
        """
        if len(buffer) < 6:
            return None

        magic = buffer[0]

        # --- MAVLink v1 ---
        if magic == 0xFE:
            payload_len = buffer[1]
            total_len = 6 + payload_len + 2
            if len(buffer) < total_len:
                return None

            seq = buffer[2]
            sys_id = buffer[3]
            comp_id = buffer[4]
            msg_id = buffer[5]
            payload = buffer[6:6 + payload_len]
            crc = struct.unpack("<H", buffer[6 + payload_len:total_len])[0]

            frame = MAVLinkFrame(
                version=1,
                magic=magic,
                payload_len=payload_len,
                incompat_flags=0,
                compat_flags=0,
                seq=seq,
                sys_id=sys_id,
                comp_id=comp_id,
                msg_id=msg_id,
                msg_name=MSG_ID_MAP.get(msg_id, f"UNKNOWN_{msg_id}"),
                payload=payload,
                crc=crc,
                is_signed=False,
                raw_frame=buffer[:total_len]
            )
            return frame, total_len

        # --- MAVLink v2 ---
        elif magic == 0xFD:
            if len(buffer) < 10:
                return None
            payload_len = buffer[1]
            incompat_flags = buffer[2]
            compat_flags = buffer[3]
            seq = buffer[4]
            sys_id = buffer[5]
            comp_id = buffer[6]
            # msg_id is 24-bit little endian
            msg_id = buffer[7] | (buffer[8] << 8) | (buffer[9] << 16)

            is_signed = bool(incompat_flags & 0x01)
            sig_len = 13 if is_signed else 0
            total_len = 10 + payload_len + 2 + sig_len

            if len(buffer) < total_len:
                return None

            payload = buffer[10:10 + payload_len]
            crc = struct.unpack("<H", buffer[10 + payload_len:10 + payload_len + 2])[0]

            sig_info = None
            if is_signed:
                sig_bytes = buffer[10 + payload_len + 2:total_len]
                link_id = sig_bytes[0]
                # 48-bit timestamp (microseconds since 2015-01-01)
                ts_raw = struct.unpack("<Q", sig_bytes[1:7] + b"\x00\x00")[0]
                sig_hash = sig_bytes[7:13].hex()
                sig_info = {
                    "link_id": link_id,
                    "timestamp_raw": ts_raw,
                    "signature_hex": sig_hash
                }

            frame = MAVLinkFrame(
                version=2,
                magic=magic,
                payload_len=payload_len,
                incompat_flags=incompat_flags,
                compat_flags=compat_flags,
                seq=seq,
                sys_id=sys_id,
                comp_id=comp_id,
                msg_id=msg_id,
                msg_name=MSG_ID_MAP.get(msg_id, f"UNKNOWN_{msg_id}"),
                payload=payload,
                crc=crc,
                is_signed=is_signed,
                signature_data=sig_info,
                raw_frame=buffer[:total_len]
            )
            return frame, total_len

        return None

    @classmethod
    def parse_stream(cls, data: bytes) -> List[MAVLinkFrame]:
        """Scans and extracts all valid frames in a byte stream, resynchronizing on error."""
        frames = []
        idx = 0
        n = len(data)

        while idx < n:
            magic = data[idx]
            if magic in (0xFE, 0xFD):
                result = cls.parse_frame(data[idx:])
                if result:
                    frame, consumed = result
                    frames.append(frame)
                    idx += consumed
                    continue
            idx += 1
        return frames

    @classmethod
    def parse_pcap(cls, pcap_path: str) -> List[MAVLinkFrame]:
        """Extracts MAVLink frames encapsulated in UDP packets from a standard PCAP file."""
        frames = []
        with open(pcap_path, "rb") as f:
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                return []
            magic = struct.unpack("<I", global_hdr[:4])[0]
            if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
                raise ValueError(f"Invalid PCAP file magic: {hex(magic)}")

            while True:
                rec_hdr = f.read(16)
                if len(rec_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", rec_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                # Expecting Ethernet (14) + IPv4 (20) + UDP (8) = 42 bytes minimum
                if len(pkt_data) >= 42:
                    eth_type = struct.unpack("!H", pkt_data[12:14])[0]
                    if eth_type == 0x0800:  # IPv4
                        ip_proto = pkt_data[23]
                        if ip_proto == 17:  # UDP
                            ihl = (pkt_data[14] & 0x0F) * 4
                            udp_offset = 14 + ihl
                            payload_offset = udp_offset + 8
                            udp_payload = pkt_data[payload_offset:]
                            parsed = cls.parse_stream(udp_payload)
                            frames.extend(parsed)

        return frames


def analyze_capture(frames: List[MAVLinkFrame]) -> Dict[str, Any]:
    """Generates comprehensive protocol audit statistics from parsed frames."""
    total = len(frames)
    v1_count = sum(1 for f in frames if f.version == 1)
    v2_count = sum(1 for f in frames if f.version == 2)
    signed_count = sum(1 for f in frames if f.is_signed)

    endpoints = {}
    message_counts = {}
    sequence_gaps = []
    last_seq_per_endpoint = {}

    for f in frames:
        ep_key = (f.sys_id, f.comp_id)
        endpoints[f"{f.sys_id}.{f.comp_id}"] = endpoints.get(f"{f.sys_id}.{f.comp_id}", 0) + 1
        message_counts[f.msg_name] = message_counts.get(f.msg_name, 0) + 1

        # Check sequence continuity
        if ep_key in last_seq_per_endpoint:
            expected_seq = (last_seq_per_endpoint[ep_key] + 1) % 256
            if f.seq != expected_seq:
                sequence_gaps.append({
                    "endpoint": f"{f.sys_id}.{f.comp_id}",
                    "expected_seq": expected_seq,
                    "observed_seq": f.seq,
                    "drop_count": (f.seq - expected_seq) % 256
                })
        last_seq_per_endpoint[ep_key] = f.seq

    return {
        "total_frames_parsed": total,
        "protocol_version_distribution": {
            "mavlink_v1": v1_count,
            "mavlink_v2": v2_count,
            "v2_percentage": round((v2_count / total * 100), 2) if total else 0.0,
        },
        "cryptographic_signing": {
            "signed_frames": signed_count,
            "unsigned_frames": total - signed_count,
            "signing_rate_percent": round((signed_count / total * 100), 2) if total else 0.0,
            "vulnerability_flag": signed_count == 0,
            "risk_summary": "Unauthenticated cleartext telemetry: susceptible to injection and spoofing" if signed_count == 0 else "MAVLink 2 signing detected"
        },
        "active_endpoints": endpoints,
        "sequence_integrity": {
            "total_anomalies_detected": len(sequence_gaps),
            "sample_anomalies": sequence_gaps[:5]
        },
        "message_frequency": sorted(message_counts.items(), key=lambda x: x[1], reverse=True)
    }


if __name__ == "__main__":
    import sys
    target_pcap = sys.argv[1] if len(sys.argv) > 1 else "evidence/telemetry_recon_baseline.pcap"
    print(f"[*] Parsing capture: {target_pcap}")
    frames = MAVLinkParser.parse_pcap(target_pcap)
    analysis = analyze_capture(frames)
    print(json.dumps(analysis, indent=2))
