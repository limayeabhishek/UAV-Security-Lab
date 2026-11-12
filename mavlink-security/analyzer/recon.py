#!/usr/bin/env python3
"""
SECUREDRONE — Protocol Reconnaissance & Telemetry Capture Engine
Stage 01 | Experiment 02: MAVLink Endpoint Reconnaissance & PCAP Generation

Captures live MAVLink datagrams over UDP, analyzes frame structure (v1 vs v2),
identifies active endpoints, and exports standard Ethernet/IP/UDP PCAP and JSON evidence.
"""

import argparse
import json
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pymavlink import mavutil


def create_pcap_global_header() -> bytes:
    """Standard libpcap global header (LinkType: Ethernet = 1)."""
    return struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # Magic number
        2, 4,        # Version 2.4
        0,           # GMT to local correction
        0,           # Accuracy of timestamps
        65535,       # Max length of captured packets (snaplen)
        1            # Link-Layer Header Type: DLT_EN10MB (Ethernet)
    )


def build_ethernet_ip_udp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Wraps UDP payload in synthetic Ethernet (II) + IPv4 + UDP headers for Wireshark."""
    # Ethernet Header (14 bytes): Dst MAC, Src MAC, EtherType (0x0800 IPv4)
    eth_hdr = struct.pack("!6s6sH", b"\x02\x00\x00\x00\x00\x02", b"\x02\x00\x00\x00\x00\x01", 0x0800)
    
    # IPv4 Header (20 bytes, no options)
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + 8 + len(payload)
    ident = 0x5432
    flags_fo = 0
    ttl = 64
    proto = 17  # UDP
    ip_chk = 0  # Placeholder for checksum calculation
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    
    ip_hdr_pre = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_len, ident, flags_fo, ttl, proto, ip_chk, src_bytes, dst_bytes)
    
    # Compute IP checksum
    chk = 0
    for i in range(0, len(ip_hdr_pre), 2):
        w = (ip_hdr_pre[i] << 8) + ip_hdr_pre[i + 1]
        chk += w
    while (chk >> 16):
        chk = (chk & 0xFFFF) + (chk >> 16)
    ip_chk = (~chk) & 0xFFFF
    ip_hdr = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_len, ident, flags_fo, ttl, proto, ip_chk, src_bytes, dst_bytes)
    
    # UDP Header (8 bytes): SrcPort, DstPort, Length, Checksum (0 = disabled)
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    
    return eth_hdr + ip_hdr + udp_hdr + payload


def wrap_pcap_packet(timestamp: float, raw_packet: bytes) -> bytes:
    """Creates a standard PCAP record header followed by raw packet data."""
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1_000_000)
    pkt_len = len(raw_packet)
    rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
    return rec_hdr + raw_packet


def run_reconnaissance(endpoint: str, duration: int, pcap_path: str, json_path: str):
    print(f"[*] SECUREDRONE Telemetry Reconnaissance starting...")
    print(f"[*] Binding to MAVLink endpoint: {endpoint}")
    print(f"[*] Acquisition window: {duration} seconds")
    
    mav = mavutil.mavlink_connection(endpoint)
    
    start_time = time.time()
    packet_count = 0
    message_stats = {}
    endpoints_seen = set()
    frames_v1 = 0
    frames_v2 = 0
    signed_frames = 0
    
    pcap_records = []
    
    while time.time() - start_time < duration:
        # Wait up to 1 second for next message
        msg = mav.recv_msg()
        if msg is None:
            time.sleep(0.01)
            continue
            
        current_ts = time.time()
        packet_count += 1
        msg_type = msg.get_type()
        src_sys = msg.get_srcSystem()
        src_comp = msg.get_srcComponent()
        endpoints_seen.add((src_sys, src_comp))
        
        # Track message frequencies
        message_stats[msg_type] = message_stats.get(msg_type, 0) + 1
        
        # Determine protocol version from raw frame buffer
        raw_bytes = msg.get_msgbuf()
        if raw_bytes and len(raw_bytes) > 0:
            magic = raw_bytes[0]
            if magic == 0xFD:
                frames_v2 += 1
                incompat_flags = raw_bytes[2] if len(raw_bytes) > 2 else 0
                if incompat_flags & 0x01:
                    signed_frames += 1
            elif magic == 0xFE:
                frames_v1 += 1
                
            # Synthesize Ethernet/IP/UDP packet for PCAP: 172.28.0.10:14550 -> 172.28.0.1:14550
            full_frame = build_ethernet_ip_udp_frame("172.28.0.10", "172.28.0.1", 14550, 14550, raw_bytes)
            pcap_records.append(wrap_pcap_packet(current_ts, full_frame))

    # Write PCAP file
    if pcap_path:
        with open(pcap_path, "wb") as f:
            f.write(create_pcap_global_header())
            for rec in pcap_records:
                f.write(rec)
        print(f"[+] PCAP evidence written to: {pcap_path} ({len(pcap_records)} frames)")
        
    # Compile JSON summary
    summary = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "duration_seconds": duration,
        "total_packets": packet_count,
        "protocol_breakdown": {
            "mavlink_v1": frames_v1,
            "mavlink_v2": frames_v2,
            "mavlink_v2_signed": signed_frames,
            "signing_enforced": signed_frames > 0 and signed_frames == frames_v2
        },
        "endpoints_discovered": [
            {"system_id": s, "component_id": c, "role": "Autopilot FMU" if c == 1 else "Subsystem"}
            for s, c in sorted(endpoints_seen)
        ],
        "message_frequency": message_stats
    }
    
    if json_path:
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Structured summary written to: {json_path}")
        
    return summary


def main():
    parser = argparse.ArgumentParser(description="SECUREDRONE MAVLink Telemetry Reconnaissance")
    parser.add_argument("--endpoint", default="udpin:0.0.0.0:14550", help="MAVLink connection string")
    parser.add_argument("--duration", type=int, default=10, help="Reconnaissance duration in seconds")
    parser.add_argument("--pcap", default="evidence/telemetry_recon_baseline.pcap", help="Output PCAP path")
    parser.add_argument("--json", default="evidence/telemetry_recon_summary.json", help="Output JSON path")
    args = parser.parse_args()
    
    summary = run_reconnaissance(args.endpoint, args.duration, args.pcap, args.json)
    print("\n--- SUMMARY REPORT ---")
    print(f"Total Packets: {summary['total_packets']}")
    print(f"MAVLink v1: {summary['protocol_breakdown']['mavlink_v1']} | MAVLink v2: {summary['protocol_breakdown']['mavlink_v2']}")
    print(f"Signed Frames: {summary['protocol_breakdown']['mavlink_v2_signed']}")
    print(f"Endpoints: {summary['endpoints_discovered']}")
    print("Top Messages:")
    for msg_name, count in sorted(summary['message_frequency'].items(), key=lambda x: x[1], reverse=True)[:8]:
        print(f"  {msg_name:<25}: {count}")


if __name__ == "__main__":
    main()
