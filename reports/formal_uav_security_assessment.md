# SECUREDRONE: Formal UAV Cybersecurity Assessment Report
**Document ID**: `SECUREDRONE-SAR-2026-001`  
**Classification**: Public Research / Technical Cybersecurity Portfolio  
**Author**: Abhishek Limaye, Senior UAV Cybersecurity Researcher  
**Target Environment**: PX4 Autopilot SITL / ArduPilot Pixhawk 4 Production Firmware / Containerized Companion Computer  
**Assessment Date**: November 2026  

---

## 1. Executive Summary

This report presents an empirical, reproducible cybersecurity assessment of unmanned aerial vehicle (UAV) systems using the SECUREDRONE research platform. Rather than relying on theoretical threat vectors or generic container vulnerability scanners, this assessment evaluates the end-to-end cyber-physical attack surface through original binary protocol dissectors, cryptographic signing auditors, companion computer API audits, production ARM Cortex-M firmware reverse engineering, and RF signal processing pipelines.

### Key Assessment Findings Summary
- **Protocol Security**: Telemetry and control links were verified to run over unauthenticated MAVLink 2 (`incompat_flags & 0x01 == 0`), enabling arbitrary packet sniffing, sequence injection, and command replay.
- **Companion Computer Trust Boundary**: Demonstrates that compromise of an offboard companion computer allows full flight controller compromise due to symmetric key sharing and the absence of a command firewall.
- **Firmware Auditing**: Unpacked official ArduPilot Pixhawk 4 production firmware (`arducopter.apj`), verified ARM Cortex-M7 Thumb-2 architecture, extracted the interrupt vector table, and mapped Flash entrypoints (`0x08008CEC`).
- **Cyber-Physical Resilience**: Validated that kinematic innovation $\chi^2$ and CUSUM drift detection successfully identify step and gradual GNSS spoofing attacks, triggering automated failsafe transitions (`ALT_HOLD` and `AUTO_LAND`).

---

## 2. Threat Model & Data-Flow Architecture

```
+--------------------------------------------------------------------------------------------------+
|                                    ZONE 0: OPERATOR / GROUND LINK                                |
|  [Ground Control Station / Assessor]                                                            |
|  - QGroundControl / Securedrone CLI (UDP 14550)                                                  |
+--------------------------------------------------------------------------------------------------+
                             |                                            |
         Cleartext Telemetry | [Trust Boundary 1: Air-Ground RF Link]     | GNSS Radio Frequency
           (Unauthenticated) |                                            | [Trust Boundary 4: Space Link]
                             v                                            v
+----------------------------------------------------+   +-----------------------------------------+
|     ZONE 1: COMPANION COMPUTER (Linux SBC)         |   |      ZONE 3: NAVIGATION SENSORS         |
|  - Insecure Mission API (Port 18088 / HTTP)        |   |  - GPS / GNSS Receiver Module           |
|  - MAVLink Firewall / Router                       |   |    (NMEA / UBX Protocol over Serial)    |
|  [Trust Boundary 2: SBC <-> Autopilot Serial Link] |   +-----------------------------------------+
+----------------------------------------------------+                        |
                             |                                                |
          MAVLink Data Bridge| (Serial / UDP 14540/14580)                     | Fix / Doppler
                             v                                                v
+--------------------------------------------------------------------------------------------------+
|                                ZONE 2: FLIGHT MANAGEMENT UNIT (FMU)                              |
|  [PX4 Autopilot / STM32F767 Cortex-M7 Core]                                                      |
|  - Commander & State Machine (Arm / Disarm / Failsafe)                                           |
|  - Navigator & Mission Manager                                                                   |
|  - ECL / EKF2 Position Estimation Filter                                                         |
|  - MAVLink Message Parser & Parameter Storage (AP_Param / bson)                                 |
+--------------------------------------------------------------------------------------------------+
```

### STRIDE Threat Classification Matrix

| Threat Category | Target UAV Subsystem | Demonstrated Attack Scenario | Demonstrated Impact |
| :--- | :--- | :--- | :--- |
| **Spoofing Identity** | MAVLink Channel / FMU | Injected packet claiming GCS identity (`sysid: 255`) | Autopilot processes commands without authenticating source |
| **Tampering** | Parameter Subsystem | Unauthorized `PARAM_SET` modifying geofence/failsafes | Flight boundary termination disabled |
| **Repudiation** | Symmetric MAVLink 2 Signing | Compromised companion signs malicious command with shared key | Indistinguishable from legitimate GCS transmission |
| **Information Disclosure** | Telemetry Stream (UDP 14550) | Passive capture of `GLOBAL_POSITION_INT` & `ATTITUDE` | Real-time drone coordinates exposed in cleartext |
| **Denial of Service** | GNSS Navigation Link | Injected RF step spoofing (+65m instantaneous displacement) | EKF innovation failure; triggers automated emergency failsafe |
| **Elevation of Privilege** | Companion Computer API | Command injection in unauthenticated companion endpoint | Execution of arbitrary shell commands as system service |

---

## 3. Vulnerability Findings Register

### Finding SEC-MAV-001: Cleartext and Unsigned MAVLink 2 Telemetry & Control
- **Vulnerability ID**: `SEC-MAV-001`
- **Component**: Flight Management Unit (FMU) MAVLink Stream
- **CVSS v3.1 Score**: **8.8** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Preconditions**: Adversary has Layer 2 network adjacency or wireless intercept capabilities on the telemetry frequency band.
- **Reproduction**:
  ```bash
  python tooling/cli.py analyze evidence/telemetry_recon_baseline.pcap
  ```
- **Evidence**: [`evidence/telemetry_recon_summary.json`](file:///Users/abhisheklimaye/UAV-Security-Lab/evidence/telemetry_recon_summary.json) demonstrates that 100% of 3,748 captured packets have `incompat_flags & 0x01 == 0` (zero signed frames).
- **Impact vs. Flight Safety**: Allows eavesdropping on mission plans and injection of unauthorized waypoint updates.
- **Remediation**: Deploy MAVLink 2 cryptographic signing using `SETUP_SIGNING` and configure parameter `MAV_0_AUTH = 1`.

---

### Finding SEC-MAV-002: Susceptibility to Command Replay Attacks
- **Vulnerability ID**: `SEC-MAV-002`
- **Component**: MAVLink Transport Layer
- **CVSS v3.1 Score**: **8.1** (`CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
- **Preconditions**: Adversary captures a valid previously transmitted command datagram.
- **Reproduction**:
  ```bash
  python mavlink-security/replay/assessor.py
  ```
- **Evidence**: Live re-injection of captured byte buffers was unconditionally accepted by the target across repeated attempts (`replays_accepted: 3`).
- **Impact**: Attackers can replay critical mission commands (such as mode changes or payload release) without knowing key material or message contents.
- **Remediation**: Enforce monotonic 48-bit timestamps via MAVLink 2 signing trailers to drop replayed packets.

---

### Finding ARCH-MAV-001: Absence of Non-Repudiation in Symmetric Key Architecture
- **Vulnerability ID**: `ARCH-MAV-001`
- **Component**: MAVLink 2 Cryptographic Architecture
- **CVSS v3.1 Score**: **6.8** (`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H`)
- **Preconditions**: Adversary gains access to an authorized peripheral (e.g. companion computer or telemetry transceiver).
- **Reproduction**:
  ```bash
  python mavlink-security/authorization/trust_boundary.py
  ```
- **Demonstrated Impact**: Because MAVLink 2 signing is symmetric HMAC-SHA256, extracting the key from a compromised companion computer allows forging high-privilege GCS commands (`sysid: 255`) with mathematically valid signatures.
- **Remediation**: Isolate companion computer links to dedicated serial channels and enforce a hardware/software command filtering firewall.

---

### Finding SEC-CMP-001: Unauthenticated Companion Computer Command Injection
- **Vulnerability ID**: `SEC-CMP-001`
- **Component**: Companion Computer HTTP Mission Interface
- **CVSS v3.1 Score**: **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Preconditions**: Network reachability to companion computer port 18088.
- **Reproduction**:
  ```bash
  pytest companion-security/tests/test_companion_security.py -k "test_vulnerable_api_allows_unauthenticated_dispatch"
  ```
- **Demonstrated Impact**: Unauthenticated remote attackers can dispatch arbitrary MAVLink commands directly to the flight controller and execute remote shell commands via unvalidated diagnostic parameters.
- **Remediation**:
  1. Implement Bearer token authentication (`Authorization: Bearer <token>`).
  2. Implement `MAVLinkFirewall` blocking safety-critical commands (`MAV_CMD_DO_FLIGHTTERMINATION`, `MAV_CMD_COMPONENT_ARM_DISARM`).
  3. Enforce strict input validation using `ipaddress` literals without shell execution.

---

### Finding SEC-NAV-001: Cyber-Physical GNSS Spoofing Resilience & Failsafe Latency
- **Vulnerability ID**: `SEC-NAV-001`
- **Component**: Navigation EKF State Estimation Subsystem
- **CVSS v3.1 Score**: **7.5** (`CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H`)
- **Preconditions**: Adversary transmits synthetic RF GNSS signals with higher power than legitimate satellites.
- **Reproduction**:
  ```bash
  python navigation-security/anomaly-detection/detector.py
  ```
- **Demonstrated Impact**: Unchecked GNSS spoofing causes vehicle drift outside approved geofences or controlled flight into terrain (CFIT).
- **Remediation & Measured Verification**: Multi-layer detection (Chi-Square Innovation + CUSUM drift detection) achieves:
  - Step Spoofing: Time-to-Detect = **0 ms** (Immediate rejection -> triggers `ALT_HOLD`).
  - Coordinated Drift Spoofing: Detected within **21.7 seconds** -> triggers `AUTO_LAND`.
  - Baseline False Alarm Rate: **1.03%**.

---

## 4. Professional Competency & Artifact Verification Index

| Domain | Competency Claimed | Verified Repository Artifact | Empirical Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Protocol Analysis** | Binary MAVLink v1/v2 parsing | [`mavlink-security/analyzer/parser.py`](file:///Users/abhisheklimaye/UAV-Security-Lab/mavlink-security/analyzer/parser.py) | 3,748 frames parsed in [`evidence/telemetry_recon_baseline.pcap`](file:///Users/abhisheklimaye/UAV-Security-Lab/evidence/telemetry_recon_baseline.pcap) |
| **Applied Cryptography** | MAVLink 2 SHA-256 HMAC & Replay | [`mavlink-security/signing/auditor.py`](file:///Users/abhisheklimaye/UAV-Security-Lab/mavlink-security/signing/auditor.py) | Unit tests in [`mavlink-security/tests/test_parser.py`](file:///Users/abhisheklimaye/UAV-Security-Lab/mavlink-security/tests/test_parser.py) |
| **Companion Security** | API Audit, Hardening & MAVLink Firewall | [`companion-security/hardened-api/firewall.py`](file:///Users/abhisheklimaye/UAV-Security-Lab/companion-security/hardened-api/firewall.py) | Passing tests in [`companion-security/tests/test_companion_security.py`](file:///Users/abhisheklimaye/UAV-Security-Lab/companion-security/tests/test_companion_security.py) |
| **Firmware Reverse Eng.** | Container unpacker, Vector Table & Ghidra | [`firmware-analysis/unpackers/apj_unpacker.py`](file:///Users/abhisheklimaye/UAV-Security-Lab/firmware-analysis/unpackers/apj_unpacker.py) | Pixhawk 4 manifest at [`firmware-analysis/manifests/firmware_manifest.json`](file:///Users/abhisheklimaye/UAV-Security-Lab/firmware-analysis/manifests/firmware_manifest.json) |
| **RF Signal Processing** | 2-GFSK IQ Demodulation & CRC-16 | [`rf-analysis/signal-processing/iq_demodulator.py`](file:///Users/abhisheklimaye/UAV-Security-Lab/rf-analysis/signal-processing/iq_demodulator.py) | IQ dataset at [`rf-analysis/datasets/telemetry_sik_915mhz.iq`](file:///Users/abhisheklimaye/UAV-Security-Lab/rf-analysis/datasets/telemetry_sik_915mhz.iq) & plot |
| **Cyber-Physical Safety** | GNSS Spoofing Detection & Failsafes | [`navigation-security/anomaly-detection/detector.py`](file:///Users/abhisheklimaye/UAV-Security-Lab/navigation-security/anomaly-detection/detector.py) | Benchmark report at [`reports/navigation_integrity_report.json`](file:///Users/abhisheklimaye/UAV-Security-Lab/reports/navigation_integrity_report.json) & plot |
| **Automated Verification** | CI/CD Regression Test Suite | Full pytest test suite | **13 passed in 1.65 seconds** |

---

## 5. Defensive Hardening & Verification Matrix

| Vulnerability / Weakness | Baseline State (Vulnerable) | Hardened State (Mitigated) | Verification Test |
| :--- | :--- | :--- | :--- |
| **Cleartext Telemetry** | Unsigned MAVLink 2 frames accepted | MAVLink 2 HMAC-SHA256 signature required | `mavlink-security/tests/test_parser.py` |
| **Replay Attacks** | Duplicate frames accepted unconditionally | Monotonic 48-bit timestamp window enforced | `mavlink-security/replay/assessor.py` |
| **Companion Remote Execution** | Unauthenticated dispatch & root execution | Bearer token auth + non-root UID 1000 | `companion-security/tests/test_companion_security.py` |
| **Disallowed Companion Commands** | Flight termination command (ID 185) passed | MAVLink Firewall intercepts and blocks ID 185 | `test_firewall_blocks_critical_commands` |
| **GNSS Spoofing Disruption** | Aircraft follows spoofed coordinates | $\chi^2$ and CUSUM trigger `ALT_HOLD` / `AUTO_LAND` | `navigation-security/anomaly-detection/detector.py` |
| **RF Framing Tampering** | Raw bitstream corrupted | CRC-16-CCITT integrity verification drops corrupted frames | `rf-analysis/signal-processing/test_rf_demod.py` |

---

## 6. Conclusion & Roadmap to Release 1.0.0

The SECUREDRONE research platform has achieved full empirical validation across simulation, protocol analysis, companion computer hardening, firmware static analysis, and wireless signal resilience. All code, datasets, and reports are structured for independent reproducibility, with zero proprietary dependencies or unverified assertions.

### Next Steps for Public Release
1. Publish repository to GitHub under the Apache-2.0 open-source license.
2. Maintain structured documentation for academic research and portfolio review.
3. Conduct further hardware-in-the-loop (HIL) testing using physical SDR transceivers and flight controllers.
