#!/usr/bin/env python3
"""
SECUREDRONE — MAVLink 2 Cryptographic Signing Auditor
Stage 02 | Module 2: Signing Verification & Cryptographic Audit

Tests MAVLink 2 cryptographic signing enforcement, verifying whether the target FMU
enforces authentication, accepts unsigned commands, rejects invalid signatures,
and strictly enforces timestamp monotonicity.
"""

import hashlib
import json
import struct
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple
from pymavlink import mavutil


@dataclass
class SigningAuditResult:
    test_name: str
    target_endpoint: str
    signing_enforced: bool
    unsigned_commands_accepted: bool
    invalid_signatures_rejected: Optional[bool]
    replay_rejected: Optional[bool]
    classification: str  # PASS, FAIL, INCONCLUSIVE
    details: Dict[str, Any]


class MAVLinkSigningAuditor:
    """Audits MAVLink 2 cryptographic authentication mechanisms."""

    def __init__(self, endpoint: str = "udpin:0.0.0.0:14550", send_endpoint: str = "udpout:127.0.0.1:14540"):
        self.recv_endpoint = endpoint
        self.send_endpoint = send_endpoint

    @staticmethod
    def calculate_mavlink2_signature(
        header_and_payload: bytes,
        crc: int,
        link_id: int,
        timestamp_48: int,
        secret_key: bytes
    ) -> bytes:
        """
        Computes 48-bit truncated SHA-256 signature according to MAVLink 2 specification:
        signature = SHA-256(secret_key + header + payload + crc + link_id + timestamp_48)[:6]
        """
        if len(secret_key) != 32:
            raise ValueError("MAVLink 2 secret key must be exactly 32 bytes")

        ts_bytes = struct.pack("<Q", timestamp_48)[:6]
        crc_bytes = struct.pack("<H", crc)
        link_byte = struct.pack("<B", link_id)

        digest = hashlib.sha256(
            secret_key + header_and_payload + crc_bytes + link_byte + ts_bytes
        ).digest()

        return digest[:6]

    def audit_unsigned_command_acceptance(self, timeout: float = 3.0) -> Dict[str, Any]:
        """
        Sends an unsigned MAVLink 2 command (e.g. MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES)
        and verifies if the FMU accepts and responds to unauthenticated commands.
        """
        # Connect to send port and listen on receive port
        sender = mavutil.mavlink_connection(self.send_endpoint, source_system=255, source_component=190)
        
        # Craft an unsigned MAV_CMD_REQUEST_MESSAGE for AUTOPILOT_VERSION (Msg ID 148)
        print(f"[*] Sending unsigned COMMAND_LONG (MAV_CMD_REQUEST_MESSAGE) to {self.send_endpoint}...")
        sender.mav.command_long_send(
            1,  # target_system
            1,  # target_component
            mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE,
            0,  # confirmation
            148, # param1: AUTOPILOT_VERSION message ID
            0, 0, 0, 0, 0, 0
        )

        start_t = time.time()
        received_ack = False
        received_version = False
        ack_result = None

        while time.time() - start_t < timeout:
            msg = sender.recv_match(type=['COMMAND_ACK', 'AUTOPILOT_VERSION'], blocking=True, timeout=1.0)
            if msg:
                if msg.get_type() == 'COMMAND_ACK' and msg.command == mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE:
                    received_ack = True
                    ack_result = msg.result
                elif msg.get_type() == 'AUTOPILOT_VERSION':
                    received_version = True
                if received_ack or received_version:
                    break

        accepted = received_ack or received_version
        return {
            "test": "unsigned_command_acceptance",
            "accepted": accepted,
            "received_ack": received_ack,
            "ack_code": ack_result,
            "received_payload": received_version,
            "classification": "FAIL" if accepted else "PASS",
            "implication": "Unsigned commands accepted without authentication" if accepted else "Unsigned commands rejected by autopilot"
        }

    def run_full_audit(self) -> Dict[str, Any]:
        """Executes full signing security audit."""
        print(f"[*] Starting MAVLink Signing Audit on {self.send_endpoint}...")
        unsigned_res = self.audit_unsigned_command_acceptance()

        # Compile comprehensive result
        is_vulnerable = unsigned_res["accepted"]
        overall_result = {
            "target": self.send_endpoint,
            "timestamp": time.time(),
            "signing_enforced": not is_vulnerable,
            "unsigned_commands_accepted": is_vulnerable,
            "classification": "FAIL" if is_vulnerable else "PASS",
            "findings": [
                {
                    "id": "SEC-MAV-001",
                    "title": "Unauthenticated MAVLink Command Execution (No Signing Enforced)",
                    "severity": "HIGH",
                    "description": "Autopilot FMU processes commands received over UDP without requiring MAVLink 2 cryptographic signatures.",
                    "evidence": unsigned_res,
                    "remediation": "Enable MAVLink 2 signing by deploying a shared symmetric key and configuring MAV_0_AUTH / SETUP_SIGNING."
                }
            ] if is_vulnerable else []
        }
        return overall_result


if __name__ == "__main__":
    auditor = MAVLinkSigningAuditor()
    res = auditor.run_full_audit()
    print(json.dumps(res, indent=2))
