"""
Automated Unit Tests for SECUREDRONE RF Demodulator & GNSS Integrity Detector
"""

import os
import numpy as np
import pytest
from rf_analysis.signal_processing.iq_demodulator import GFSKSignalPipeline
from navigation_security.anomaly_detection.detector import GNSSAnomalyDetector


def test_gfsk_signal_demodulation_and_crc():
    pipeline = GFSKSignalPipeline(sample_rate=1_000_000, symbol_rate=50_000, f_dev=25_000)
    test_payload = "TEST_MAVLINK_TELEMETRY"
    raw_pkt, iq_samples = pipeline.synthesize_telemetry_frame(test_payload)

    result = pipeline.demodulate(iq_samples)
    assert result["status"] == "PASS"
    assert result["sync_acquired"] is True
    assert result["crc_valid"] is True
    assert result["recovered_payload_ascii"] == test_payload


def test_gnss_step_and_drift_detection():
    detector = GNSSAnomalyDetector()
    dataset = detector.generate_synthetic_flight_dataset()
    results = detector.run_detection_pipeline(dataset)

    metrics = results["metrics"]
    assert metrics["step_spoofing_detected"] is True
    assert metrics["drift_spoofing_detected"] is True
    assert metrics["step_attack_time_to_detect_ms"] <= 100
    assert metrics["baseline_false_alarm_rate_pct"] < 5.0
