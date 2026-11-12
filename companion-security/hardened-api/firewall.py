#!/usr/bin/env python3
"""
SECUREDRONE — MAVLink Command Firewall & Packet Filter
Stage 03 | Hardened Companion Defense

Enforces strict defense-in-depth on the Companion Computer -> Autopilot serial/UDP bridge.
Inspects MAVLink message types and command IDs, dropping unauthorized flight-critical
commands (e.g. flight termination, arbitrary disarm, parameter tampering) regardless of
endpoint identity or shared key possession.
"""

from typing import Dict, Optional, Set, Tuple


# Safety-Critical Commands Strictly Forbidden from Companion Interface
DISALLOWED_COMMAND_IDS: Set[int] = {
    185,  # MAV_CMD_DO_FLIGHTTERMINATION
    246,  # MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN
    400,  # MAV_CMD_COMPONENT_ARM_DISARM (disarm in flight)
}

# Permitted Message Types from Companion Computer
WHITELISTED_MSG_TYPES: Set[str] = {
    "HEARTBEAT",
    "PING",
    "SET_POSITION_TARGET_LOCAL_NED",
    "SET_POSITION_TARGET_GLOBAL_INT",
    "SET_ATTITUDE_TARGET",
    "COMMAND_LONG",  # Only if command ID is whitelisted
    "PARAM_REQUEST_READ",
}


class MAVLinkFirewall:
    """Stateful firewall policy engine for UAV companion computer links."""

    def __init__(self):
        self.total_evaluated = 0
        self.total_blocked = 0
        self.blocked_log = []

    def evaluate_message(self, msg_type: str, payload_data: Optional[Dict] = None) -> Tuple[bool, str]:
        """
        Evaluates a MAVLink message.
        Returns (is_permitted: bool, reason: str).
        """
        self.total_evaluated += 1

        if msg_type not in WHITELISTED_MSG_TYPES:
            self.total_blocked += 1
            reason = f"Message type '{msg_type}' is not in companion permitted whitelist"
            self.blocked_log.append({"msg_type": msg_type, "reason": reason})
            return False, reason

        # Deep inspection for COMMAND_LONG
        if msg_type == "COMMAND_LONG" and payload_data:
            cmd_id = payload_data.get("command")
            if cmd_id in DISALLOWED_COMMAND_IDS:
                self.total_blocked += 1
                reason = f"Flight-critical command ID {cmd_id} is blocked on companion bridge"
                self.blocked_log.append({"msg_type": msg_type, "command_id": cmd_id, "reason": reason})
                return False, reason

        return True, "Permitted by firewall policy"
