"""
Automated Unit Tests for SECUREDRONE Firmware Unpacker & Vector Table Analyzer
"""

import os
import struct
import pytest
from firmware_analysis.unpackers.apj_unpacker import APJFirmwareUnpacker


def test_firmware_unpacking_and_vector_table():
    apj_path = "firmware-analysis/manifests/arducopter_pixhawk4.apj"
    out_bin = "firmware-analysis/manifests/test_output.bin"
    
    if not os.path.exists(apj_path):
        pytest.skip("Firmware artifact not found")

    unpacker = APJFirmwareUnpacker(apj_path)
    manifest = unpacker.unpack(out_bin)

    # 1. Verify container metadata
    assert manifest["artifact_info"]["board_id"] == 50
    assert manifest["artifact_info"]["container_format"] == "APJFWv1"
    assert "STM32F7" in manifest["artifact_info"]["target_mcu"]

    # 2. Verify binary size
    assert manifest["binary_extraction"]["binary_size_bytes"] == 1564244
    assert os.path.exists(out_bin)
    assert os.path.getsize(out_bin) == 1564244

    # 3. Verify ARM Cortex-M Vector Table Invariants
    initial_sp = int(manifest["memory_layout"]["initial_stack_pointer"], 16)
    reset_handler = int(manifest["memory_layout"]["reset_handler_raw"], 16)

    # SP must reside in SRAM (0x20000000 - 0x20080000)
    assert 0x20000000 <= initial_sp <= 0x20080000

    # Reset Handler must reside in Flash (0x08008000 - 0x08200000)
    assert 0x08008000 <= reset_handler <= 0x08200000

    # Thumb bit must be set (bit 0 == 1)
    assert manifest["memory_layout"]["thumb_bit_set"] is True
    assert (reset_handler & 0x01) == 1

    # Cleanup test output
    if os.path.exists(out_bin):
        os.remove(out_bin)
