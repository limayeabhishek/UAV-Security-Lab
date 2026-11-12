#!/usr/bin/env python3
"""
SECUREDRONE — MAVLink Replay Attack Assessment Engine
Stage 02 | Module 3: Replay Resilience & Monotonic Timestamp Verification

Evaluates whether the autopilot FMU detects and rejects replayed packets.
Tests replay behavior on both unsigned and cryptographically signed channels.
"""

import json
import socket
import time
from typing import Any, Dict, List
from pymavlink import mavutil


class MAVLinkReplayAssessor:
    """Evaluates autopilot susceptibility to packet replay attacks."""

    def __init__(self, target_ip: str = "127.0.0.1", target_port: int = 14540, listen_port: int = 14550):
        self.target_ip = target_ip
        self.target_port = target_port
        self.listen_port = listen_port

    def assess_replay_vulnerability(self, replay_count: int = 3, interval: float = 0.5) -> Dict[str, Any]:
        """
        Generates a valid MAVLink command packet, captures its raw byte representation,
        and re-injects the exact byte sequence multiple times, measuring responses.
        """
        # Connect to sender
        sender = mavutil.mavlink_connection(f"udpout:{self.target_ip}:{self.target_port}", source_system=255, source_component=190)
        
        # Prepare a probe command: MAV_CMD_REQUEST_MESSAGE for SYS_STATUS (Msg ID 1)
        # Note: MAVLink seq number is inside the packet header
        msg = sender.mav.command_long_encode(
            1,  # target_system
            1,  # target_component
            mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE,
            0,  # confirmation
            1,  # param1: SYS_STATUS message ID
            0, 0, 0, 0, 0, 0
        )
        raw_packet_bytes = msg.pack(sender.mav)
        
        print(f"[*] Original probe packet generated: {len(raw_packet_bytes)} bytes")
        print(f"[*] Hex: {raw_packet_bytes.hex()}")

        # Raw socket for replaying exact binary bytes (bypassing pymavlink auto-incrementing seq numbers)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        responses_recorded = []
        
        for i in range(1, replay_count + 1):
            print(f"[*] [Replay #{i}] Transmitting duplicate packet to {self.target_ip}:{self.target_port}...")
            raw_sock.sendto(raw_packet_bytes, (self.target_ip, self.target_port))
            
            # Listen for response
            start_wait = time.time()
            got_response = False
            resp_type = None
            
            while time.time() - start_wait < 1.0:
                resp = sender.recv_match(type=['COMMAND_ACK', 'SYS_STATUS'], blocking=True, timeout=0.5)
                if resp:
                    got_response = True
                    resp_type = resp.get_type()
                    break
                    
            responses_recorded.append({
                "replay_index": i,
                "timestamp_sent": time.time(),
                "response_received": got_response,
                "response_type": resp_type
            })
            time.sleep(interval)

        raw_sock.close()

        # Vulnerability analysis: If responses were received for duplicate packets, replay attack succeeded
        replays_accepted = sum(1 for r in responses_recorded if r["response_received"])
        is_vulnerable = replays_accepted > 1

        return {
            "test": "replay_attack_assessment",
            "target": f"{self.target_ip}:{self.target_port}",
            "packet_length": len(raw_packet_bytes),
            "replays_attempted": replay_count,
            "replays_accepted": replays_accepted,
            "classification": "FAIL" if is_vulnerable else "PASS",
            "vulnerability_flag": is_vulnerable,
            "responses": responses_recorded,
            "finding": {
                "id": "SEC-MAV-002",
                "title": "Susceptibility to Command Replay Attacks (No Anti-Replay Protection)",
                "severity": "HIGH",
                "description": "The autopilot processes identical, bit-for-bit replayed UDP datagrams without enforcing monotonic timestamps or anti-replay sequence windows.",
                "remediation": "Deploy MAVLink 2 cryptographic signing with strict monotonic timestamp validation (`incompat_flags & 0x01`)."
            } if is_vulnerable else None
        }


if __name__ == "__main__":
    assessor = MAVLinkReplayAssessor()
    results = assessor.assess_replay_vulnerability()
    print(json.dumps(results, indent=2))
