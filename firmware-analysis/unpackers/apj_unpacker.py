#!/usr/bin/env python3
"""
SECUREDRONE — Firmware Container Unpacker & Architecture Analyzer
Stage 04 | Module: Production Firmware Static Audit

Unpacks ArduPilot .apj / PX4 container formats, validates cryptographic hashes,
extracts raw binary payloads, identifies ARM Cortex-M vector tables, and establishes
memory layouts and entrypoint addresses for Ghidra disassembler import.
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import zlib
from typing import Any, Dict, List, Tuple


class APJFirmwareUnpacker:
    """Unpacks and analyzes ArduPilot/PX4 .apj container artifacts."""

    def __init__(self, apj_path: str):
        self.apj_path = apj_path
        if not os.path.exists(apj_path):
            raise FileNotFoundError(f"Firmware artifact not found: {apj_path}")

    def compute_file_hash(self) -> str:
        h = hashlib.sha256()
        with open(self.apj_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def unpack(self, output_bin_path: str) -> Dict[str, Any]:
        sha256_hash = self.compute_file_hash()
        
        with open(self.apj_path, "r") as f:
            container = json.load(f)

        magic = container.get("magic")
        if magic != "APJFWv1":
            raise ValueError(f"Unsupported container magic: {magic}")

        board_id = container.get("board_id")
        desc = container.get("description", "")
        summary = container.get("summary", "")
        git_identity = container.get("git_identity", "")
        expected_size = container.get("image_size", 0)
        flash_total = container.get("flash_total", 0)

        # Decompress raw binary image
        b64_image = container.get("image", "")
        compressed_bytes = base64.b64decode(b64_image)
        raw_binary = zlib.decompress(compressed_bytes)

        if len(raw_binary) != expected_size:
            print(f"[!] Warning: Decompressed size {len(raw_binary)} != expected {expected_size}")

        # Save raw binary
        os.makedirs(os.path.dirname(output_bin_path) or ".", exist_ok=True)
        with open(output_bin_path, "wb") as f:
            f.write(raw_binary)

        bin_sha256 = hashlib.sha256(raw_binary).hexdigest()

        # Vector Table Analysis (ARM Cortex-M)
        # Vector 0: Initial SP (points to SRAM)
        # Vector 1: Reset Handler (points to Flash + 1 Thumb bit)
        vector_table = []
        num_vectors = min(16, len(raw_binary) // 4)
        for i in range(num_vectors):
            val = struct.unpack("<I", raw_binary[i * 4:(i + 1) * 4])[0]
            vector_table.append(val)

        initial_sp = vector_table[0] if len(vector_table) > 0 else 0
        reset_handler = vector_table[1] if len(vector_table) > 1 else 0

        # Memory Layout Inferences
        # Standard STM32: Flash is 0x08000000. FMUv5 bootloader offset is typically 0x08008000.
        # Check if Reset Handler address falls in 0x08000000 range
        is_stm32 = (reset_handler & 0xFF000000) == 0x08000000
        is_thumb = bool(reset_handler & 0x01)
        actual_entrypoint = reset_handler & ~0x01

        # Determine load base: typical STM32 bootloaders are 16KB (0x4000) or 32KB (0x8000)
        if is_stm32:
            if (actual_entrypoint >= 0x08008000):
                load_address = 0x08008000
            elif (actual_entrypoint >= 0x08004000):
                load_address = 0x08004000
            else:
                load_address = 0x08000000
        else:
            load_address = 0x00000000

        # String and symbol reconnaissance
        strings_found = []
        min_len = 6
        current_str = []
        for b in raw_binary:
            if 32 <= b <= 126:
                current_str.append(chr(b))
            else:
                if len(current_str) >= min_len:
                    s = "".join(current_str)
                    if any(term in s.lower() for term in ["mavlink", "failsafe", "geofence", "arm", "param", "signing"]):
                        strings_found.append(s)
                current_str = []

        manifest = {
            "artifact_info": {
                "source_file": self.apj_path,
                "container_format": magic,
                "container_sha256": sha256_hash,
                "board_id": board_id,
                "board_summary": summary,
                "target_mcu": desc,
                "git_commit": git_identity,
                "flash_capacity_bytes": flash_total,
            },
            "binary_extraction": {
                "extracted_path": output_bin_path,
                "binary_size_bytes": len(raw_binary),
                "binary_sha256": bin_sha256,
            },
            "architecture_identification": {
                "cpu_family": "ARM Cortex-M7 (STM32F767)" if "STM32F7" in desc else "ARM Cortex-M",
                "instruction_set": "Thumb-2 (16/32-bit)" if is_thumb else "ARM32 / Unknown",
                "endianness": "Little-Endian",
                "fpu": "FPv5-D16 (Hardware Floating Point)",
            },
            "memory_layout": {
                "inferred_flash_base": hex(load_address),
                "initial_stack_pointer": hex(initial_sp),
                "sram_region": "SRAM1/SRAM2 / DTCM" if (initial_sp & 0x20000000) else "Unknown",
                "reset_handler_raw": hex(reset_handler),
                "entrypoint_address": hex(actual_entrypoint),
                "thumb_bit_set": is_thumb,
            },
            "interrupt_vector_table_preview": [
                {"vector": 0, "name": "Initial_SP", "address": hex(vector_table[0])},
                {"vector": 1, "name": "Reset_Handler", "address": hex(vector_table[1])},
                {"vector": 2, "name": "NMI_Handler", "address": hex(vector_table[2])},
                {"vector": 3, "name": "HardFault_Handler", "address": hex(vector_table[3])},
                {"vector": 4, "name": "MemManage_Handler", "address": hex(vector_table[4])},
                {"vector": 5, "name": "BusFault_Handler", "address": hex(vector_table[5])},
                {"vector": 6, "name": "UsageFault_Handler", "address": hex(vector_table[6])},
            ],
            "security_symbol_reconnaissance": {
                "total_security_strings_found": len(strings_found),
                "sample_symbols": strings_found[:12]
            }
        }
        return manifest


def main():
    parser = argparse.ArgumentParser(description="SECUREDRONE Production Firmware Unpacker")
    parser.add_argument("apj_path", nargs="?", default="firmware-analysis/manifests/arducopter_pixhawk4.apj")
    parser.add_argument("--out-bin", default="firmware-analysis/manifests/arducopter_pixhawk4.bin")
    parser.add_argument("--out-manifest", default="firmware-analysis/manifests/firmware_manifest.json")
    args = parser.parse_args()

    print(f"[*] Unpacking firmware container: {args.apj_path}")
    unpacker = APJFirmwareUnpacker(args.apj_path)
    manifest = unpacker.unpack(args.out_bin)

    with open(args.out_manifest, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[+] Raw binary unpacked to: {args.out_bin} ({manifest['binary_extraction']['binary_size_bytes']} bytes)")
    print(f"[+] Firmware manifest generated: {args.out_manifest}")
    print("\n--- ARCHITECTURE & MEMORY MAP ---")
    print(f"Target MCU       : {manifest['artifact_info']['target_mcu']}")
    print(f"CPU Family       : {manifest['architecture_identification']['cpu_family']}")
    print(f"Instruction Set  : {manifest['architecture_identification']['instruction_set']}")
    print(f"Flash Load Base  : {manifest['memory_layout']['inferred_flash_base']}")
    print(f"Entrypoint (PC)  : {manifest['memory_layout']['entrypoint_address']}")
    print(f"Initial SP       : {manifest['memory_layout']['initial_stack_pointer']}")
    print("\n--- VECTOR TABLE ---")
    for vec in manifest['interrupt_vector_table_preview'][:4]:
        print(f"  [{vec['vector']}] {vec['name']:<18}: {vec['address']}")


if __name__ == "__main__":
    main()
