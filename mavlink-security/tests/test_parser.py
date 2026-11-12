"""
Automated Unit Tests for SECUREDRONE MAVLink Binary Parser
"""

import os
import struct
import pytest
from mavlink_security.analyzer.parser import MAVLinkParser, MAVLinkFrame, analyze_capture


def test_parse_mavlink_v1_synthetic():
    # Construct synthetic MAVLink v1 HEARTBEAT
    # Magic: 0xFE, Len: 9, Seq: 12, Sys: 1, Comp: 1, MsgId: 0
    payload = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    crc = 0xABCD
    v1_raw = struct.pack("<BBBBBB", 0xFE, 9, 12, 1, 1, 0) + payload + struct.pack("<H", crc)
    
    result = MAVLinkParser.parse_frame(v1_raw)
    assert result is not None
    frame, consumed = result
    assert frame.version == 1
    assert frame.magic == 0xFE
    assert frame.payload_len == 9
    assert frame.seq == 12
    assert frame.sys_id == 1
    assert frame.comp_id == 1
    assert frame.msg_id == 0
    assert frame.msg_name == "HEARTBEAT"
    assert frame.is_signed is False
    assert consumed == len(v1_raw)


def test_parse_mavlink_v2_synthetic():
    # Construct synthetic MAVLink v2 frame
    # Magic: 0xFD, Len: 4, Incompat: 0, Compat: 0, Seq: 42, Sys: 1, Comp: 1, MsgId: 30 (ATTITUDE)
    payload = b"\x11\x22\x33\x44"
    crc = 0x1234
    msg_id = 30
    header = struct.pack(
        "<BBBBBBB",
        0xFD, 4, 0, 0, 42, 1, 1
    ) + struct.pack("<I", msg_id)[:3]
    v2_raw = header + payload + struct.pack("<H", crc)

    result = MAVLinkParser.parse_frame(v2_raw)
    assert result is not None
    frame, consumed = result
    assert frame.version == 2
    assert frame.magic == 0xFD
    assert frame.seq == 42
    assert frame.msg_id == 30
    assert frame.msg_name == "ATTITUDE"
    assert frame.is_signed is False
    assert consumed == len(v2_raw)


def test_parse_mavlink_v2_signed_synthetic():
    # Construct synthetic signed MAVLink v2 frame (incompat_flags = 0x01)
    payload = b"\xAA\xBB"
    crc = 0x5678
    link_id = 2
    ts_48 = b"\x01\x02\x03\x04\x05\x06"
    sig_hash = b"\xDE\xAD\xBE\xEF\xCA\xFE"
    signature = struct.pack("<B", link_id) + ts_48 + sig_hash

    msg_id = 76  # COMMAND_LONG
    header = struct.pack(
        "<BBBBBBB",
        0xFD, len(payload), 0x01, 0, 100, 255, 1
    ) + struct.pack("<I", msg_id)[:3]
    v2_signed_raw = header + payload + struct.pack("<H", crc) + signature

    result = MAVLinkParser.parse_frame(v2_signed_raw)
    assert result is not None
    frame, consumed = result
    assert frame.version == 2
    assert frame.is_signed is True
    assert frame.msg_name == "COMMAND_LONG"
    assert frame.signature_data is not None
    assert frame.signature_data["link_id"] == 2
    assert frame.signature_data["signature_hex"] == "deadbeefcafe"
    assert consumed == len(v2_signed_raw)


def test_parse_truncated_buffer():
    # Only 4 bytes (less than min header)
    truncated = b"\xFD\x05\x00\x00"
    assert MAVLinkParser.parse_frame(truncated) is None


def test_parse_baseline_pcap():
    pcap_path = "evidence/telemetry_recon_baseline.pcap"
    if os.path.exists(pcap_path):
        frames = MAVLinkParser.parse_pcap(pcap_path)
        assert len(frames) > 0
        analysis = analyze_capture(frames)
        assert analysis["total_frames_parsed"] == len(frames)
        assert analysis["protocol_version_distribution"]["v2_percentage"] == 100.0
