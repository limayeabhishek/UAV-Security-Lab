#!/usr/bin/env python3
"""
SECUREDRONE — MAVLink Parameter Security Auditor
Stage 02 | Module 4: Parameter Access Control & Safety Failsafe Verification

Audits MAVLink parameter read/write access controls. Inspects safety-critical
failsafe and geofence parameters, tests whether write operations require
authentication, and documents safety integrity implications.
"""

import json
import struct
import time
from typing import Any, Dict, List, Optional
from pymavlink import mavutil


# Safety-critical parameters across PX4 and ArduPilot
CRITICAL_SAFETY_PARAMS = [
    {"name": "GF_ACTION", "description": "Geofence violation failsafe action"},
    {"name": "GF_MAX_HOR_DIST", "description": "Maximum horizontal geofence distance"},
    {"name": "NAV_RCL_ACT", "description": "RC signal loss failsafe action"},
    {"name": "NAV_DLL_ACT", "description": "Data link (telemetry) loss failsafe action"},
    {"name": "COM_RC_IN_MODE", "description": "RC transmitter input authorization mode"},
    {"name": "CBRK_IO_SAFETY", "description": "Circuit breaker for hardware safety switch"},
]


class MAVLinkParameterAuditor:
    """Audits MAVLink parameter security, access control, and failsafe configurations."""

    def __init__(self, endpoint: str = "udpout:127.0.0.1:14540", recv_endpoint: str = "udpin:0.0.0.0:14550"):
        self.endpoint = endpoint
        self.recv_endpoint = recv_endpoint

    def read_parameter(self, param_name: str, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
        """Sends PARAM_REQUEST_READ and listens for PARAM_VALUE."""
        conn = mavutil.mavlink_connection(self.endpoint, source_system=255, source_component=190)
        
        # PARAM_REQUEST_READ
        param_id_bytes = param_name.encode('utf-8').ljust(16, b'\x00')
        conn.mav.param_request_read_send(
            1,  # target_system
            1,  # target_component
            param_id_bytes,
            -1  # param_index (-1 means use param_id)
        )

        start_t = time.time()
        while time.time() - start_t < timeout:
            msg = conn.recv_match(type='PARAM_VALUE', blocking=True, timeout=0.5)
            if msg:
                # Clean param_id string
                msg_param_id = msg.param_id
                if isinstance(msg_param_id, bytes):
                    msg_param_id = msg_param_id.decode('utf-8', errors='ignore').rstrip('\x00')
                elif isinstance(msg_param_id, str):
                    msg_param_id = msg_param_id.rstrip('\x00')

                if msg_param_id == param_name:
                    return {
                        "param_id": msg_param_id,
                        "value": msg.param_value,
                        "param_type": msg.param_type,
                        "param_index": msg.param_index,
                        "param_count": msg.param_count
                    }
        return None

    def audit_parameter_write_protection(self, target_param: str = "GF_ACTION", timeout: float = 3.0) -> Dict[str, Any]:
        """
        Tests whether PARAM_SET requires authentication.
        Safely reads current value, attempts to write the identical value, and observes if write is accepted.
        """
        print(f"[*] Auditing write authorization on safety parameter: {target_param}...")
        current = self.read_parameter(target_param, timeout=2.0)
        
        if not current:
            return {
                "test": "parameter_write_authorization",
                "param_tested": target_param,
                "classification": "INCONCLUSIVE",
                "reason": f"Target parameter '{target_param}' not returned by autopilot"
            }

        original_val = current["value"]
        param_type = current["param_type"]
        param_id_bytes = target_param.encode('utf-8').ljust(16, b'\x00')

        # Connect as an unauthenticated external entity
        conn = mavutil.mavlink_connection(self.endpoint, source_system=255, source_component=190)
        
        # Attempt PARAM_SET with the SAME value (harmless idempotent test)
        conn.mav.param_set_send(
            1, 1,
            param_id_bytes,
            float(original_val),
            param_type
        )

        # Autopilot emits PARAM_VALUE on successful parameter change
        write_confirmed = False
        start_t = time.time()
        while time.time() - start_t < timeout:
            msg = conn.recv_match(type='PARAM_VALUE', blocking=True, timeout=0.5)
            if msg:
                msg_param_id = msg.param_id
                if isinstance(msg_param_id, bytes):
                    msg_param_id = msg_param_id.decode('utf-8', errors='ignore').rstrip('\x00')
                elif isinstance(msg_param_id, str):
                    msg_param_id = msg_param_id.rstrip('\x00')

                if msg_param_id == target_param:
                    write_confirmed = True
                    break

        return {
            "test": "parameter_write_authorization",
            "param_tested": target_param,
            "original_value": original_val,
            "unauthenticated_write_accepted": write_confirmed,
            "classification": "FAIL" if write_confirmed else "PASS",
            "finding": {
                "id": "SEC-MAV-003",
                "title": "Unauthenticated Parameter Modification",
                "severity": "HIGH",
                "description": f"The autopilot accepts PARAM_SET writes from unauthenticated network entities for critical parameter '{target_param}'.",
                "remediation": "Restrict parameter modifications to cryptographically signed MAVLink channels or local companion USB connections."
            } if write_confirmed else None
        }

    def scan_safety_parameters(self) -> Dict[str, Any]:
        """Queries inventory of key flight-safety and geofence parameters."""
        print("[*] Scanning autopilot safety-critical parameters...")
        inventory = {}
        for item in CRITICAL_SAFETY_PARAMS:
            res = self.read_parameter(item["name"], timeout=1.0)
            if res:
                inventory[item["name"]] = {
                    "description": item["description"],
                    "value": res["value"],
                    "type": res["param_type"]
                }
                print(f"    [+] {item['name']:<18}: {res['value']}")
            else:
                print(f"    [-] {item['name']:<18}: Not found")

        return inventory


if __name__ == "__main__":
    auditor = MAVLinkParameterAuditor()
    inv = auditor.scan_safety_parameters()
    write_test = auditor.audit_parameter_write_protection()
    print("\n--- PARAMETER AUDIT RESULTS ---")
    print(json.dumps({"inventory": inv, "write_test": write_test}, indent=2))
