# Stage 01: UAV Simulation & Protocol Reconnaissance

## 1. Executive Summary & Objective
Stage 01 establishes an independently reproducible UAV software-in-the-loop (SITL) simulation environment, identifies network endpoints, intercepts telemetry flows, and empirically validates MAVLink v1 and v2 binary framing structures.

## 2. Environment Architecture & Trust Boundaries

```
+-----------------------------------------------------------------------------------------+
|                                      macOS HOST                                         |
|  [Operator / Assessor Workstation]                                                      |
|  - Securedrone CLI / Analyzer (127.0.0.1:14550)                                         |
|  - Wireshark / Network Packet Inspector                                                 |
+-----------------------------------------------------------------------------------------+
                               |                                ^
                  UDP Telemetry|                                | UDP Control Commands
                    (Port 14550)|                                | (Port 14540 / 14550)
                               v                                |
+-----------------------------------------------------------------------------------------+
|                                    DOCKER NETWORK                                       |
|  Bridge Network: uav_security_net (172.28.0.0/24)                                        |
|  Target Container: uav-target-drone (172.28.0.10)                                       |
|                                                                                         |
|  +-----------------------------------------------------------------------------------+  |
|  | [PX4 Autopilot SITL]                                                              |  |
|  | - FMU Core Process: px4 (PID 96)                                                  |  |
|  | - Simulator Bridge: Gazebo Harmonic gz_x500 (UDP 18570)                           |  |
|  | - MAVLink Instance 0 (GCS Stream): Outbound UDP -> 172.28.0.1:14550               |  |
|  | - MAVLink Instance 1 (Offboard / Companion): Inbound UDP 14540 / 14580            |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

### Trust Boundary Analysis
1. **Air-Ground Telemetry Link (UDP 14550)**:
   - Primary data link transmitting state estimation (attitude, global position, GPS satellites, battery status).
   - Currently operating over cleartext UDP without encryption or transport-layer integrity protection.
2. **Offboard / Companion Interface (UDP 14540)**:
   - Designed for high-rate companion computer control, trajectory setpoints, and offboard mission directives.
   - Accepts unsigned commands by default.

---

## 3. Empirical Protocol Analysis

### Frame Breakdown & Wire Characteristics
Telemetry was captured during a 10-second baseline acquisition window via `mavlink-security/analyzer/recon.py`, producing `evidence/telemetry_recon_baseline.pcap` (3,748 frames, 364 KB).

| Property | Value | Observation & Security Implications |
| :--- | :--- | :--- |
| **Total Captured Frames** | 3,748 | Sustained telemetry stream at ~375 msgs/sec |
| **MAVLink Version** | MAVLink 2 (0xFD) | 100% of captured frames utilize MAVLink 2 framing |
| **Active System IDs** | System 1, Component 1 | Autopilot Flight Management Unit (FMU) |
| **MAVLink 2 Signing Flag** | `0` (Unsigned) | **0% of packets contain signatures (`incompat_flags & 0x01 == 0`)** |
| **Sequence Continuity** | 100% | Zero packet drop detected during local loopback |

### Wire Format Comparison

#### MAVLink v1 Packet (Legacy)
```
[0xFE][LEN][SEQ][SYS_ID][COMP_ID][MSG_ID (8-bit)][PAYLOAD (0-255B)][CRC (16-bit)]
```
- Maximum 256 unique message types.
- No native cryptographic signing support.
- Vulnerable to unauthenticated injection and parameter tampering.

#### MAVLink v2 Packet (Current Target Baseline)
```
[0xFD][LEN][INCOMPAT][COMPAT][SEQ][SYS_ID][COMP_ID][MSG_ID (24-bit)][PAYLOAD][CRC][OPTIONAL SIGNATURE (13B)]
```
- Supports 24-bit message IDs (up to 16,777,216 message types).
- Incompatible flags byte:
  - Bit 0 (`0x01`): Signed packet (`MAVLINK_IFLAG_SIGNED`).
- Optional 13-byte signature trailer:
  - 1 byte `link_id`
  - 6 bytes (48-bit) `timestamp` (prevents replay attacks)
  - 6 bytes (48-bit) `signature` (truncated SHA-256 HMAC)

---

## 4. Key Telemetry Message Inventory

From the captured baseline, the highest-frequency messages identified:
1. `ATTITUDE` / `ATTITUDE_QUATERNION` (Msg ID 30 / 31): High-rate pitch, roll, yaw Euler angles and angular velocity quaternions.
2. `GLOBAL_POSITION_INT` (Msg ID 33): Fused GPS/EKF latitude, longitude, relative altitude, and velocity vectors.
3. `LOCAL_POSITION_NED` (Msg ID 32): Local North-East-Down Cartesian coordinate odometry.
4. `GPS_RAW_INT` (Msg ID 24): Raw GNSS fix type, HDOP, VDOP, satellite count, and lat/lon integers.
5. `HEARTBEAT` (Msg ID 0): Autopilot system status, armed status (`base_mode`), vehicle type (`MAV_TYPE_QUADROTOR`), and flight mode (`custom_mode`).

---

## 5. Security Findings & Next Phase
- **Observation 01-A**: All telemetry is transmitted unencrypted and unauthenticated. Any agent listening on port 14550 can passively intercept complete flight telemetry, vehicle location, and internal state.
- **Observation 01-B**: The target FMU accepts commands without verifying cryptographic signatures by default.
- **Transition to Stage 02**: Develop the original MAVLink Security Assessment Framework to audit signature verification, parameter tampering, command injection, and replay protection.
