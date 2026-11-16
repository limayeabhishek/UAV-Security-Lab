#!/usr/bin/env python3
"""
SECUREDRONE — Unified Security Assessment CLI
Main orchestration interface for MAVLink security evaluation, replay testing,
parameter auditing, and companion-computer assessments.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mavlink_security.analyzer.parser import MAVLinkParser, analyze_capture
from mavlink_security.analyzer.recon import run_reconnaissance
from mavlink_security.signing.auditor import MAVLinkSigningAuditor
from mavlink_security.replay.assessor import MAVLinkReplayAssessor
from mavlink_security.parameters.auditor import MAVLinkParameterAuditor
from mavlink_security.authorization.trust_boundary import TrustBoundaryAssessor


def banner():
    print(r"""
========================================================================
   ____ ____ ____ _   _ ____  _____ ____  ____   ___  _   _ _____ 
  / ___|  _ \___ \ | | |  _ \| ____|  _ \|  _ \ / _ \| \ | | ____|
  \___ \ | | |__) | | | | |_) |  _| | | | | |_) | | | |  \| |  _|  
   ___) | |_| / __/| |_| |  _ <| |___| |_| |  _ <| |_| | |\  | |___ 
  |____/|____/_____|\___/|_| \_\_____|____/|_| \_\\___/|_| \_|_____|
             UAV Security Research & Assessment Platform
========================================================================
""")


def run_full_assessment(target_in: str, target_out: str, output_report: str):
    banner()
    print("[+] Initiating Full MAVLink Security Assessment Suite...")
    print(f"[+] Target Inbound: {target_in} | Target Outbound: {target_out}")
    print(f"[+] Report Destination: {output_report}\n")

    report = {
        "assessment_id": f"SECUREDRONE-MAV-{int(time.time())}",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "target_endpoints": {"listen": target_in, "send": target_out},
        "modules_evaluated": [],
        "findings": [],
        "overall_status": "COMPLETED"
    }

    # 1. Reconnaissance & Telemetry Frame Audit
    print("--- [MODULE 1] Protocol Analysis & Telemetry Audit ---")
    pcap_path = "evidence/telemetry_recon_baseline.pcap"
    recon_json = "evidence/telemetry_recon_summary.json"
    if not os.path.exists(pcap_path):
        recon_data = run_reconnaissance(target_in, duration=5, pcap_path=pcap_path, json_path=recon_json)
    frames = MAVLinkParser.parse_pcap(pcap_path)
    analysis = analyze_capture(frames)
    report["modules_evaluated"].append({"module": "protocol_analyzer", "result": analysis})

    if analysis["cryptographic_signing"]["vulnerability_flag"]:
        report["findings"].append({
            "id": "SEC-MAV-001",
            "title": "Cleartext and Unsigned MAVLink 2 Telemetry",
            "severity": "HIGH",
            "cvss_v31": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.8)",
            "impact": "Passive adversaries can intercept telemetry and inject arbitrary commands.",
            "remediation": "Enable MAVLink 2 signing with a 256-bit secret key across all data links."
        })

    # 2. Signing Auditor
    print("\n--- [MODULE 2] MAVLink 2 Cryptographic Signing Auditor ---")
    signing_auditor = MAVLinkSigningAuditor(endpoint=target_in, send_endpoint=target_out)
    signing_res = signing_auditor.run_full_audit()
    report["modules_evaluated"].append({"module": "signing_auditor", "result": signing_res})
    for f in signing_res.get("findings", []):
        if not any(existing["id"] == f["id"] for existing in report["findings"]):
            report["findings"].append(f)

    # 3. Replay Assessment
    print("\n--- [MODULE 3] Replay Attack Assessment ---")
    host, port = target_out.replace("udpout:", "").split(":")
    replay_assessor = MAVLinkReplayAssessor(target_ip=host, target_port=int(port))
    replay_res = replay_assessor.assess_replay_vulnerability(replay_count=3)
    report["modules_evaluated"].append({"module": "replay_assessor", "result": replay_res})
    if replay_res.get("finding"):
        report["findings"].append(replay_res["finding"])

    # 4. Parameter Security
    print("\n--- [MODULE 4] Parameter Security & Access Control ---")
    param_auditor = MAVLinkParameterAuditor(endpoint=target_out, recv_endpoint=target_in)
    param_inv = param_auditor.scan_safety_parameters()
    param_write = param_auditor.audit_parameter_write_protection()
    report["modules_evaluated"].append({
        "module": "parameter_auditor",
        "inventory": param_inv,
        "write_audit": param_write
    })
    if param_write.get("finding"):
        report["findings"].append(param_write["finding"])

    # 5. Trust Boundary & Identity Spoofing
    print("\n--- [MODULE 5] Trust Boundary & Authorization Assessment ---")
    trust_assessor = TrustBoundaryAssessor(target_endpoint=target_out)
    spoof_res = trust_assessor.test_identity_spoofing()
    shared_key_res = trust_assessor.simulate_shared_key_compromise_model()
    report["modules_evaluated"].append({
        "module": "trust_boundary",
        "spoofing": spoof_res,
        "shared_key_analysis": shared_key_res
    })
    if shared_key_res.get("cryptographic_finding"):
        report["findings"].append(shared_key_res["cryptographic_finding"])

    # Compile and save
    os.makedirs(os.path.dirname(output_report) or ".", exist_ok=True)
    with open(output_report, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 72)
    print(f"[+] ASSESSMENT COMPLETE! Formal report saved to: {output_report}")
    print(f"[+] Total Verified Findings Identified: {len(report['findings'])}")
    for f in report["findings"]:
        print(f"    - [{f['id']}] {f.get('title', 'Finding')} ({f.get('severity', 'UNKNOWN')})")
    print("=" * 72)
    return report


def main():
    parser = argparse.ArgumentParser(description="SECUREDRONE UAV Security Assessment Platform")
    subparsers = parser.add_subparsers(dest="command")

    # recon
    recon_parser = subparsers.add_parser("recon", help="Capture and analyze live MAVLink telemetry")
    recon_parser.add_argument("--endpoint", default="udpin:0.0.0.0:14550")
    recon_parser.add_argument("--duration", type=int, default=10)
    recon_parser.add_argument("--pcap", default="evidence/telemetry_recon_baseline.pcap")
    recon_parser.add_argument("--json", default="evidence/telemetry_recon_summary.json")

    # analyze
    analyze_parser = subparsers.add_parser("analyze", help="Parse and audit a PCAP capture")
    analyze_parser.add_argument("pcap_path", default="evidence/telemetry_recon_baseline.pcap", nargs="?")

    # audit-all
    audit_parser = subparsers.add_parser("audit-all", help="Execute complete Stage 02 assessment suite")
    audit_parser.add_argument("--target-in", default="udpin:0.0.0.0:14550")
    audit_parser.add_argument("--target-out", default="udpout:127.0.0.1:14540")
    audit_parser.add_argument("--output", default="reports/mavlink_security_assessment_report.json")

    args = parser.parse_args()

    if args.command == "recon":
        run_reconnaissance(args.endpoint, args.duration, args.pcap, args.json)
    elif args.command == "analyze":
        frames = MAVLinkParser.parse_pcap(args.pcap_path)
        res = analyze_capture(frames)
        print(json.dumps(res, indent=2))
    elif args.command == "audit-all":
        run_full_assessment(args.target_in, args.target_out, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
