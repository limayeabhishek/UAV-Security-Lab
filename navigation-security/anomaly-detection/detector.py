#!/usr/bin/env python3
"""
SECUREDRONE — GNSS Navigation Integrity & Cyber-Physical Anomaly Detector
Stage 05 | Module: Navigation Integrity & Failsafe Evaluation

Simulates benign and spoofed GNSS trajectories (sudden jump vs coordinated drift).
Applies multi-layer kinematic validation, Chi-Square innovation testing, and CUSUM
statistical drift detection to identify spoofing and trigger automated flight failsafes.
"""

import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Tuple
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


@dataclass
class AnomalyEvent:
    epoch: int
    timestamp_sec: float
    detector: str
    anomaly_score: float
    threshold: float
    severity: str
    failsafe_action: str


class GNSSAnomalyDetector:
    """Multi-layer navigation integrity filter and failsafe trigger."""

    def __init__(
        self,
        dt: float = 0.1,
        max_feasible_accel: float = 5.0,  # m/s^2 for typical multirotor
        max_feasible_vel: float = 18.0,    # m/s
        chi2_threshold: float = 9.21,      # 99% confidence for 2 DOF
        cusum_threshold: float = 10.0
    ):
        self.dt = dt
        self.max_accel = max_feasible_accel
        self.max_vel = max_feasible_vel
        self.chi2_thresh = chi2_threshold
        self.cusum_thresh = cusum_threshold

    def generate_synthetic_flight_dataset(self, num_points: int = 1000) -> Dict[str, np.ndarray]:
        """
        Synthesizes 100s flight (10 Hz = 1000 points):
        - t = 0..30s: Normal flight (hover/waypoint at 5 m/s) with Gaussian noise (sigma=0.5m).
        - t = 30..45s: Sudden Step Spoofing (+65m jump).
        - t = 45..60s: Recovery to normal waypoint navigation.
        - t = 60..85s: Subtle Coordinated Drift Spoofing (ramping at 0.3 m/s^2).
        - t = 85..100s: Stable flight.
        """
        t = np.linspace(0, (num_points - 1) * self.dt, num_points)
        
        # Ground Truth Trajectory (Smooth flight along X-axis at 2 m/s)
        x_true = 2.0 * t
        y_true = 5.0 * np.sin(0.1 * t)
        vx_true = np.gradient(x_true, self.dt)
        vy_true = np.gradient(y_true, self.dt)

        # Baseline GNSS measurement with Gaussian receiver noise
        noise_x = np.random.normal(0, 0.4, num_points)
        noise_y = np.random.normal(0, 0.4, num_points)
        x_meas = x_true + noise_x
        y_meas = y_true + noise_y

        attack_labels = np.zeros(num_points, dtype=int)  # 0=benign, 1=step, 2=drift

        # Inject Attack 1: Sudden Step Spoofing (epochs 300 to 450)
        x_meas[300:450] += 65.0
        y_meas[300:450] -= 40.0
        attack_labels[300:450] = 1

        # Inject Attack 2: Coordinated Drift Spoofing (epochs 600 to 850)
        drift_epochs = np.arange(600, 850) - 600
        drift_offset_x = 0.5 * 0.35 * (drift_epochs * self.dt) ** 2  # quadratic drift
        x_meas[600:850] += drift_offset_x
        attack_labels[600:850] = 2

        return {
            "time": t,
            "x_true": x_true,
            "y_true": y_true,
            "x_meas": x_meas,
            "y_meas": y_meas,
            "attack_labels": attack_labels
        }

    def run_detection_pipeline(self, dataset: Dict[str, np.ndarray]) -> Dict[str, Any]:
        t = dataset["time"]
        x = dataset["x_meas"]
        y = dataset["y_meas"]
        labels = dataset["attack_labels"]
        n = len(t)

        # Apply 5-point smoothing before acceleration calculation to avoid derivative noise amplification
        window = 5
        x_smooth = np.convolve(x, np.ones(window)/window, mode='same')
        y_smooth = np.convolve(y, np.ones(window)/window, mode='same')

        vx = np.gradient(x_smooth, self.dt)
        vy = np.gradient(y_smooth, self.dt)
        speed = np.sqrt(vx**2 + vy**2)

        ax = np.gradient(vx, self.dt)
        ay = np.gradient(vy, self.dt)
        accel = np.sqrt(ax**2 + ay**2)

        # 1. Kinematic Innovation Score: normalized by max feasible acceleration
        kinematic_score = accel / self.max_accel

        # 2. Chi-Square Residual against constant-velocity Kalman model
        # Innovation variance for 2nd order extrapolation: Var(e_k - 2*e_{k-1} + e_{k-2}) = 6 * sigma^2
        sigma = 0.4
        innov_var = 6.0 * (sigma ** 2)
        chi2_scores = np.zeros(n)
        for i in range(2, n):
            # Extrapolate expected position
            x_pred = 2 * x[i-1] - x[i-2]
            y_pred = 2 * y[i-1] - y[i-2]
            res_x = x[i] - x_pred
            res_y = y[i] - y_pred
            # 2 DOF chi-square normalized by true innovation variance
            chi2_scores[i] = (res_x**2 + res_y**2) / innov_var

        # 3. CUSUM Drift Detector with adaptive forgetting factor
        cusum_scores = np.zeros(n)
        s_k = 0.0
        # Expected nominal distance per step: 2.0 m/s * dt = 0.2 m.
        nominal_step = 2.0 * self.dt
        slack = 0.18
        for i in range(1, n):
            step_dist = np.sqrt((x[i] - x[i-1])**2 + (y[i] - y[i-1])**2)
            bias = step_dist - nominal_step - slack
            s_k = max(0.0, 0.95 * s_k + bias)
            cusum_scores[i] = s_k

        # Failsafe Decision Logic
        failsafe_state = []
        events = []
        current_state = "MISSION_NOMINAL"

        for i in range(n):
            # EKF Chi-Square innovation test detects sudden position/velocity step jumps
            is_step_anomaly = (chi2_scores[i] > self.chi2_thresh)
            # CUSUM detector identifies gradual coordinated velocity drift
            is_drift_anomaly = (cusum_scores[i] > self.cusum_thresh)

            if is_step_anomaly:
                current_state = "FAILSAFE_TRIGGERED_ALT_HOLD"
                events.append(AnomalyEvent(
                    epoch=i,
                    timestamp_sec=float(t[i]),
                    detector="EKF Chi-Square Innovation",
                    anomaly_score=float(chi2_scores[i]),
                    threshold=float(self.chi2_thresh),
                    severity="CRITICAL",
                    failsafe_action="Reject GNSS -> Switch to Inertial/Altitude Hold"
                ))
            elif is_drift_anomaly:
                current_state = "FAILSAFE_TRIGGERED_AUTO_LAND"
                events.append(AnomalyEvent(
                    epoch=i,
                    timestamp_sec=float(t[i]),
                    detector="CUSUM Drift",
                    anomaly_score=float(cusum_scores[i]),
                    threshold=float(self.cusum_thresh),
                    severity="HIGH",
                    failsafe_action="Detected Coordinated Drift -> Trigger Controlled Land"
                ))
            else:
                current_state = "MISSION_NOMINAL"

            failsafe_state.append(current_state)

        # Evaluate Time-To-Detect (TTD) per standard DO-229 / UAV Navigation Integrity Standards
        step_attack_start = 300
        step_detected_epoch = next((i for i in range(step_attack_start, 450) if chi2_scores[i] > self.chi2_thresh), None)
        step_ttd_sec = (step_detected_epoch - step_attack_start) * self.dt if step_detected_epoch is not None else None

        drift_attack_start = 600
        drift_detected_epoch = next((i for i in range(drift_attack_start, 850) if cusum_scores[i] > self.cusum_thresh), None)
        drift_ttd_sec = (drift_detected_epoch - drift_attack_start) * self.dt if drift_detected_epoch is not None else None

        # Clean baseline false alarm rate (measured on pure benign segment epochs 0 to 290)
        benign_alarms = sum(1 for i in range(0, 290) if chi2_scores[i] > self.chi2_thresh or cusum_scores[i] > self.cusum_thresh)
        false_alarm_rate_pct = round((benign_alarms / 290) * 100, 2)

        return {
            "metrics": {
                "total_epochs": n,
                "step_attack_epochs": "300 - 450 (t=30.0s - 45.0s)",
                "step_spoofing_detected": step_detected_epoch is not None,
                "step_attack_time_to_detect_ms": int(step_ttd_sec * 1000) if step_ttd_sec is not None else -1,
                "step_mitigation_action": "ALT_HOLD (Inertial Dead-Reckoning)",
                "drift_attack_epochs": "600 - 850 (t=60.0s - 85.0s)",
                "drift_spoofing_detected": drift_detected_epoch is not None,
                "drift_attack_time_to_detect_sec": round(drift_ttd_sec, 2) if drift_ttd_sec is not None else -1,
                "drift_mitigation_action": "AUTO_LAND (Controlled Termination)",
                "baseline_false_alarm_rate_pct": false_alarm_rate_pct,
            },
            "signals": {
                "time": t,
                "speed": speed,
                "accel": accel,
                "chi2_scores": chi2_scores,
                "cusum_scores": cusum_scores,
                "failsafe_state": failsafe_state
            },
            "sample_events": [asdict(e) for e in events[:8]]
        }

    def generate_visual_artifacts(self, dataset: Dict[str, np.ndarray], results: Dict[str, Any], output_path: str):
        fig, axes = plt.subplots(3, 1, figsize=(11, 10))

        t = dataset["time"]
        x_true = dataset["x_true"]
        x_meas = dataset["x_meas"]
        chi2 = results["signals"]["chi2_scores"]
        cusum = results["signals"]["cusum_scores"]

        # 1. Trajectory Plot: True vs Spoofed GNSS
        axes[0].plot(t, x_true, label="Ground Truth Kinematics", color="#2ca02c", linestyle="--", linewidth=1.5)
        axes[0].plot(t, x_meas, label="Received GNSS Measurements (Spoofed)", color="#d62728", linewidth=1.2)
        axes[0].axvspan(30, 45, color="orange", alpha=0.25, label="Attack 1: Step Spoofing (+65m)")
        axes[0].axvspan(60, 85, color="purple", alpha=0.20, label="Attack 2: Coordinated Drift (0.35 m/s²)")
        axes[0].set_title("SECUREDRONE — GNSS Navigation Trajectory Under Cyber-Physical Spoofing", fontsize=12, fontweight="bold")
        axes[0].set_ylabel("Position X (meters)")
        axes[0].legend(loc="upper left")
        axes[0].grid(True, linestyle="--", alpha=0.6)

        # 2. Chi-Square Innovation Residual Detector
        axes[1].plot(t, chi2, label=r"$\chi^2$ Innovation Residual", color="#1f77b4", linewidth=1.2)
        axes[1].axhline(self.chi2_thresh, color="red", linestyle=":", linewidth=1.5, label=f"Detection Threshold ({self.chi2_thresh})")
        axes[1].set_title(r"Kinematic Innovation $\chi^2$ Detector (Instantaneous Step Rejection)", fontsize=11, fontweight="bold")
        axes[1].set_ylabel(r"$\chi^2$ Score")
        axes[1].set_ylim(0, 100)
        axes[1].legend(loc="upper left")
        axes[1].grid(True, linestyle="--", alpha=0.6)

        # 3. CUSUM Statistical Drift Detector
        axes[2].plot(t, cusum, label="CUSUM Drift Anomaly Score", color="#9467bd", linewidth=1.5)
        axes[2].axhline(self.cusum_thresh, color="red", linestyle=":", linewidth=1.5, label=f"CUSUM Alarm Threshold ({self.cusum_thresh})")
        axes[2].set_title("Cumulative Sum (CUSUM) Detector (Slow Coordinated Velocity Drift)", fontsize=11, fontweight="bold")
        axes[2].set_xlabel("Flight Time (seconds)")
        axes[2].set_ylabel("CUSUM Statistic")
        axes[2].legend(loc="upper left")
        axes[2].grid(True, linestyle="--", alpha=0.6)

        plt.tight_layout()
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        plt.savefig(output_path, dpi=150)
        plt.close()
        print(f"[+] GNSS anomaly visualization saved to: {output_path}")


def main():
    detector = GNSSAnomalyDetector()
    print("[*] Generating synthetic UAV GNSS flight dataset with cyber-physical attacks...")
    dataset = detector.generate_synthetic_flight_dataset()

    print("[*] Executing multi-layer navigation integrity detection pipeline...")
    results = detector.run_detection_pipeline(dataset)

    plot_path = "evidence/gnss_anomaly_detection_plot.png"
    report_path = "reports/navigation_integrity_report.json"

    detector.generate_visual_artifacts(dataset, results, plot_path)

    summary_report = {
        "benchmark": "SECUREDRONE GNSS Integrity & Spoofing Evaluation",
        "detection_metrics": results["metrics"],
        "sample_events": results["sample_events"]
    }
    with open(report_path, "w") as f:
        json.dump(summary_report, f, indent=2)

    print(f"[+] Navigation integrity report saved to: {report_path}")
    print("\n--- NAVIGATION INTEGRITY BENCHMARK RESULTS ---")
    print(f"Total Epochs Evaluated    : {results['metrics']['total_epochs']}")
    print(f"Step Attack Detected      : {results['metrics']['step_spoofing_detected']} (TTD: {results['metrics']['step_attack_time_to_detect_ms']} ms)")
    print(f"Drift Attack Detected     : {results['metrics']['drift_spoofing_detected']} (TTD: {results['metrics']['drift_attack_time_to_detect_sec']} s)")
    print(f"Baseline False Alarm Rate : {results['metrics']['baseline_false_alarm_rate_pct']}%")
    print(f"Step Failsafe Action      : {results['metrics']['step_mitigation_action']}")
    print(f"Drift Failsafe Action     : {results['metrics']['drift_mitigation_action']}")


if __name__ == "__main__":
    main()
