#!/usr/bin/env python3
"""
SECUREDRONE — Vulnerable Companion Computer Mission API
Stage 03 | Vulnerable Companion Implementation

Demonstrates common real-world security weaknesses in drone companion computers:
1. Unauthenticated administrative / mission endpoints.
2. Insecure remote command dispatch into MAVLink router without filtering.
3. Command injection vulnerability in waypoint processing / system utilities.
4. Execution under privileged root account without sandboxing.
"""

import http.server
import json
import os
import socket
import urllib.parse
from typing import Any, Dict


class VulnerableCompanionHandler(http.server.BaseHTTPRequestHandler):
    """Vulnerable HTTP API handler without authentication or input validation."""

    def _send_json(self, status: int, data: Dict[str, Any]):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Powered-By", "SECUREDRONE-VulnerableCompanion/1.0")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/v1/status":
            self._send_json(200, {
                "status": "online",
                "service": "companion-mission-controller",
                "running_user": os.popen("whoami").read().strip(),
                "uid": os.getuid() if hasattr(os, "getuid") else 0,
                "auth_enforced": False
            })
        elif parsed.path == "/api/v1/telemetry":
            self._send_json(200, {
                "altitude_m": 45.2,
                "battery_pct": 88,
                "gps_fix": 3,
                "armed": False,
                "mode": "HOLD"
            })
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)
        
        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        # Vulnerability 1: Arbitrary unauthenticated command dispatch
        if parsed.path == "/api/v1/command/dispatch":
            command = payload.get("command")
            target_sys = payload.get("target_system", 1)
            target_comp = payload.get("target_component", 1)
            
            # Forwards directly to simulated flight-controller without permission checking
            self._send_json(200, {
                "status": "DISPATCHED",
                "dispatched_command": command,
                "target_system": target_sys,
                "target_component": target_comp,
                "authenticated": False,
                "message": "Command transmitted directly to flight controller MAVLink bridge"
            })

        # Vulnerability 2: Shell Command Injection in diagnostic tool
        elif parsed.path == "/api/v1/diagnostics/ping":
            host = payload.get("host", "127.0.0.1")
            # Insecure string interpolation executing shell
            cmd = f"ping -c 1 {host}"
            output = os.popen(cmd).read()
            self._send_json(200, {
                "status": "COMPLETED",
                "executed": cmd,
                "output": output
            })
        else:
            self._send_json(404, {"error": "Unknown Endpoint"})


def run_vulnerable_service(port: int = 8088):
    server = http.server.HTTPServer(("0.0.0.0", port), VulnerableCompanionHandler)
    print(f"[*] SECUREDRONE Vulnerable Companion API listening on port {port}...")
    server.serve_forever()


if __name__ == "__main__":
    run_vulnerable_service()
