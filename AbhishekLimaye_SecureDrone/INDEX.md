# SECUREDRONE Research & Assessment Deliverables Package
**Researcher**: Abhishek Limaye  
**Project**: SECUREDRONE — Open UAV Security Research & Assessment Platform  
**Document Identifier**: `SECUREDRONE-SAR-2026-001`  

This standalone package contains the complete technical deliverables, research report, packet captures, reverse engineering manifests, and empirical verification plots generated during the cybersecurity evaluation.

---

## Deliverables Index

| Filename | Type | Description |
| :--- | :--- | :--- |
| **`securedrone_technical_report.pdf`** | Primary Document | Publication-grade 5-page research report authored by Abhishek Limaye, detailing threat models, equations, findings, and verified defenses. |
| **`formal_uav_security_assessment.md`** | Technical Report | Markdown edition of the formal security assessment, including full STRIDE matrices and CVSS v3.1 scoring registers. |
| **`telemetry_recon_baseline.pcap`** | Network Capture | 3,748-frame raw Ethernet/IP/UDP packet capture of live MAVLink 2 telemetry from the PX4 SITL target (viewable in Wireshark). |
| **`mavlink_security_assessment_report.json`** | Audit Telemetry | Machine-readable JSON output from the automated MAVLink security auditor (signing, replay, and trust boundaries). |
| **`firmware_manifest.json`** | Reverse Engineering | Decompressed firmware manifest from official ArduPilot Pixhawk 4 production binary (`arducopter.apj`), vector table, and memory offsets. |
| **`ghidra_loader_notes.md`** | Reverse Engineering | Static disassembly documentation and memory map boundaries for STM32F767 ARM Cortex-M7 in Ghidra. |
| **`rf_demodulation_plot.png`** | Signal Processing | High-resolution plot showing 2-GFSK telemetry Power Spectral Density (PSD) and baseband FM discriminator bitstream recovery. |
| **`gnss_anomaly_detection_plot.png`** | Cyber-Physical Security | Multi-layer GNSS spoofing trajectory plot showing EKF $\chi^2$ innovation residuals and CUSUM drift detection failsafe engagement. |
| **`navigation_integrity_report.json`** | Benchmark Data | Quantitative performance metrics and event logs from the GNSS spoofing benchmark. |
