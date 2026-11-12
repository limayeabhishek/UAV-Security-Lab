"""
Automated Security Tests for Companion Computer APIs & MAVLink Firewall
"""

import threading
import time
import urllib.request
import urllib.error
import json
import pytest
from companion_security.hardened_api.firewall import MAVLinkFirewall
from companion_security.hardened_api.server import HardenedCompanionHandler
from companion_security.vulnerable_api.server import VulnerableCompanionHandler
import http.server


def test_firewall_blocks_critical_commands():
    fw = MAVLinkFirewall()

    # Flight Termination command (ID 185)
    permitted, reason = fw.evaluate_message("COMMAND_LONG", {"command": 185})
    assert permitted is False
    assert "blocked" in reason.lower()

    # Disarm / Arm command (ID 400)
    permitted, reason = fw.evaluate_message("COMMAND_LONG", {"command": 400})
    assert permitted is False

    # Arbitrary non-whitelisted message type (e.g. PARAM_SET)
    permitted, reason = fw.evaluate_message("PARAM_SET", {"param_id": "GF_ACTION"})
    assert permitted is False


def test_firewall_permits_safe_setpoints():
    fw = MAVLinkFirewall()

    # Offboard velocity / position setpoint
    permitted, reason = fw.evaluate_message("SET_POSITION_TARGET_LOCAL_NED", {"x": 10.0, "y": 0.0})
    assert permitted is True

    # Benign takeoff command (ID 22)
    permitted, reason = fw.evaluate_message("COMMAND_LONG", {"command": 22})
    assert permitted is True


class TestLiveCompanionAPIs:
    @classmethod
    def setup_class(cls):
        # Start vulnerable server on 18088
        cls.vuln_server = http.server.HTTPServer(("127.0.0.1", 18088), VulnerableCompanionHandler)
        cls.vuln_thread = threading.Thread(target=cls.vuln_server.serve_forever, daemon=True)
        cls.vuln_thread.start()

        # Start hardened server on 18089
        cls.hard_server = http.server.HTTPServer(("127.0.0.1", 18089), HardenedCompanionHandler)
        cls.hard_thread = threading.Thread(target=cls.hard_server.serve_forever, daemon=True)
        cls.hard_thread.start()
        time.sleep(0.2)

    @classmethod
    def teardown_class(cls):
        cls.vuln_server.shutdown()
        cls.hard_server.shutdown()

    def test_vulnerable_api_allows_unauthenticated_dispatch(self):
        url = "http://127.0.0.1:18088/api/v1/command/dispatch"
        data = json.dumps({"command": "EMERGENCY_DISARM"}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode())
            assert body["status"] == "DISPATCHED"
            assert body["authenticated"] is False

    def test_hardened_api_rejects_unauthenticated_access(self):
        url = "http://127.0.0.1:18089/api/v1/status"
        req = urllib.request.Request(url)
        
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 401

    def test_hardened_api_accepts_valid_token_and_blocks_dangerous_command(self):
        url = "http://127.0.0.1:18089/api/v1/command/dispatch"
        token = "uav_sec_key_9f8e7d6c5b4a3"
        
        # Test 1: Attempt to dispatch flight termination (ID 185)
        dangerous_payload = json.dumps({
            "msg_type": "COMMAND_LONG",
            "data": {"command": 185}
        }).encode("utf-8")

        req = urllib.request.Request(url, data=dangerous_payload, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        })

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == 403
        error_body = json.loads(exc_info.value.read().decode())
        assert error_body["status"] == "BLOCKED_BY_FIREWALL"

        # Test 2: Dispatch benign offboard setpoint
        safe_payload = json.dumps({
            "msg_type": "SET_POSITION_TARGET_LOCAL_NED",
            "data": {"x": 5.0}
        }).encode("utf-8")

        req_safe = urllib.request.Request(url, data=safe_payload, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        })
        with urllib.request.urlopen(req_safe) as resp:
            assert resp.status == 200
            res_json = json.loads(resp.read().decode())
            assert res_json["status"] == "ACCEPTED"
