"""Round-by-round diagnostics and plots for the IoT trust simulator.

This module does not use attack ground truth to calculate trust or decisions.
The optional scenario label is stored only for post-run visualization/evaluation.
"""
from __future__ import annotations

import csv
import json
import os
from collections.abc import Mapping
from typing import Any


FIELDS = [
    "round", "device_id", "device_type", "scenario_label",
    "behavior_score", "context_score", "history_score", "risk_score",
    "trust_score", "resource_capability", "resource_pressure",
    "behavior_weight", "context_weight", "history_weight", "risk_weight",
    "evidence_strength", "behavior_penalty_observed", "context_penalty_observed",
    "history_penalty_observed", "risk_elevation_observed", "decision", "security_action",
    "observation_timestamp", "source", "temperature", "humidity", "motion_detected",
    "hour", "minute", "second", "fps", "image_size_bytes", "raw_payload",
    "detection_result", "integrity_status", "device_hmac_valid", "adaptive_weights",
]


def _number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        if result != result:  # NaN
            return default
        return max(0.0, min(1.0, result))
    except (TypeError, ValueError):
        return default


def _find_number(obj: Any, keys: tuple[str, ...], default: float = 0.0) -> float:
    """Read a numeric key from common adaptive-weight result shapes."""
    def search(value: Any):
        if isinstance(value, Mapping):
            for key in keys:
                if key in value:
                    try:
                        return _number(value[key])
                    except (TypeError, ValueError):
                        pass
            for child in value.values():
                found = search(child)
                if found is not None:
                    return found
        return None
    found = search(obj)
    return default if found is None else found


def observed_evidence_strength(data: dict, behavior_score: float, context_score: float) -> float:
    """A transparent evidence index from observable indicators, not a probability.

    Flags are weighted and normalized. Scores from analyzers are used as corroborating
    indicators. Keep these weights configurable and validate them experimentally.
    """
    indicators = {
        "malicious_activity": (bool(data.get("malicious_activity", False)), 0.30),
        "unexpected_network": (bool(data.get("unexpected_network", False)), 0.20),
        "unauthorized_command": (bool(data.get("unauthorized_command", False)), 0.25),
        "malicious_status": (str(data.get("status", "")).lower() == "malicious", 0.10),
        "abnormal_behavior": (behavior_score < 0.40, 0.10),
        "abnormal_context": (context_score < 0.40, 0.05),
    }
    return round(sum(weight for observed, weight in indicators.values() if observed), 3)


class ExperimentVisualizer:
    def __init__(self, output_dir: str = "experiments/results"):
        self.output_dir = output_dir
        self.rows: list[dict[str, Any]] = []

    def record(
        self, *, round_number: int, device, data: dict,
        behavior_score: float, context_score: float, history_score: float,
        risk_score: float, trust_score: float, rcf: float,
        resource_pressure: float, adaptive_weights: Any,
        decision_result: dict, scenario_label: str = "NORMAL",
    ) -> None:
        """Save one row per device per round. scenario_label is evaluation metadata only."""
        evidence = observed_evidence_strength(data, behavior_score, context_score)
        self.rows.append({
            "round": int(round_number),
            "device_id": getattr(device, "device_id", data.get("device_id", "UNKNOWN")),
            "device_type": getattr(device, "device_type", data.get("device_type", "UNKNOWN")),
            "scenario_label": scenario_label,
            "behavior_score": _number(behavior_score),
            "context_score": _number(context_score),
            "history_score": _number(history_score),
            "risk_score": _number(risk_score),
            "trust_score": _number(trust_score),
            "resource_capability": _number(rcf),
            "resource_pressure": _number(resource_pressure),
            "behavior_weight": _find_number(adaptive_weights, ("behavior", "behavior_weight", "w_behavior")),
            "context_weight": _find_number(adaptive_weights, ("context", "context_weight", "w_context")),
            "history_weight": _find_number(adaptive_weights, ("history", "history_weight", "w_history")),
            "risk_weight": _find_number(adaptive_weights, ("risk", "risk_weight", "w_risk")),
            "evidence_strength": evidence,
            # These are observed score deficits/elevation for plotting. They are NOT
            # extra penalties applied to the trust model, avoiding double-penalization.
            "behavior_penalty_observed": round(1.0 - _number(behavior_score), 3),
            "context_penalty_observed": round(1.0 - _number(context_score), 3),
            "history_penalty_observed": round(1.0 - _number(history_score), 3),
            "risk_elevation_observed": _number(risk_score),
            "decision": decision_result.get("decision", "UNKNOWN"),
            "security_action": decision_result.get("security_action", "UNKNOWN"),
            "observation_timestamp": data.get("timestamp") or data.get("_received_at_epoch"),
            "source": data.get("source"),
            "temperature": data.get("temperature"),
            "humidity": data.get("humidity"),
            "motion_detected": data.get("motion_detected"),
            "hour": data.get("hour"),
            "minute": data.get("minute"),
            "second": data.get("second"),
            "fps": data.get("fps"),
            "image_size_bytes": data.get("image_size_bytes"),
            "raw_payload": data.get("raw_payload"),
            "detection_result": json.dumps(
                data.get("device_attack_result", data.get("device_attack_indicators", [])),
                sort_keys=True, default=str,
            ),
            "integrity_status": data.get("integrity_status", "UNVERIFIED"),
            "device_hmac_valid": data.get("device_hmac_valid"),
            "adaptive_weights": json.dumps(adaptive_weights, sort_keys=True, default=str),
        })

    def save_and_plot(self) -> dict[str, str]:
        os.makedirs(self.output_dir, exist_ok=True)
        csv_path = os.path.join(self.output_dir, "round_metrics.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(self.rows)

        if not self.rows:
            print("[VISUALIZER] No round data collected; CSV header saved only.")
            return {"csv": csv_path}

        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import numpy as np
        except ImportError as exc:
            print(f"[VISUALIZER] matplotlib/numpy unavailable; CSV saved. {exc}")
            return {"csv": csv_path}

        paths: dict[str, str] = {"csv": csv_path}
        device_ids = sorted({str(row["device_id"]) for row in self.rows})

        def save(fig, name: str):
            path = os.path.join(self.output_dir, name)
            fig.tight_layout()
            fig.savefig(path, dpi=160, bbox_inches="tight")
            plt.close(fig)
            paths[name] = path

        # 1. Component scores and trust/risk, one line per device.
        fig, axes = plt.subplots(2, 1, figsize=(12, 9), sharex=True)
        for device_id in device_ids:
            subset = sorted((r for r in self.rows if str(r["device_id"]) == device_id), key=lambda r: r["round"])
            rounds = [r["round"] for r in subset]
            for key, label in (("behavior_score", "Behavior"), ("context_score", "Context"), ("history_score", "History")):
                axes[0].plot(rounds, [r[key] for r in subset], marker="o", linewidth=1.5, label=f"{device_id} · {label}")
            axes[1].plot(rounds, [r["trust_score"] for r in subset], marker="o", label=f"{device_id} · Trust")
            axes[1].plot(rounds, [r["risk_score"] for r in subset], linestyle="--", label=f"{device_id} · Risk")
        axes[0].set_title("Component scores by device and round")
        axes[0].set_ylabel("Score (0–1)")
        axes[1].set_title("Trust and risk trajectory")
        axes[1].set_ylabel("Score (0–1)")
        axes[1].set_xlabel("Simulation round")
        for ax in axes:
            ax.set_ylim(-0.03, 1.03)
            ax.grid(True, alpha=0.25)
            ax.legend(fontsize=7, ncol=2)
        save(fig, "component_trust_risk.png")

        # 2. Adaptive weights over rounds for each device.
        fig, ax = plt.subplots(figsize=(12, 6))
        for device_id in device_ids:
            subset = sorted((r for r in self.rows if str(r["device_id"]) == device_id), key=lambda r: r["round"])
            for key, label in (("behavior_weight", "Behavior"), ("context_weight", "Context"), ("history_weight", "History"), ("risk_weight", "Risk")):
                vals = [r[key] for r in subset]
                if any(v != 0 for v in vals):
                    ax.plot([r["round"] for r in subset], vals, marker=".", label=f"{device_id} · {label}")
        ax.set_title("Adaptive component weights by round")
        ax.set_xlabel("Simulation round")
        ax.set_ylabel("Weight")
        ax.grid(True, alpha=0.25)
        ax.legend(fontsize=7, ncol=2)
        save(fig, "adaptive_weights.png")

        # 3. Resource capability and pressure versus trust.
        fig, axes = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
        for device_id in device_ids:
            subset = sorted((r for r in self.rows if str(r["device_id"]) == device_id), key=lambda r: r["round"])
            rounds = [r["round"] for r in subset]
            axes[0].plot(rounds, [r["resource_capability"] for r in subset], marker="o", label=device_id)
            axes[1].plot(rounds, [r["resource_pressure"] for r in subset], marker="o", label=f"{device_id} · Pressure")
            axes[1].plot(rounds, [r["trust_score"] for r in subset], linestyle="--", label=f"{device_id} · Trust")
        axes[0].set_title("Resource capability")
        axes[0].set_ylabel("RCF (0–1)")
        axes[1].set_title("Resource pressure and trust")
        axes[1].set_ylabel("Score (0–1)")
        axes[1].set_xlabel("Simulation round")
        for ax in axes:
            ax.set_ylim(-0.03, 1.03)
            ax.grid(True, alpha=0.25)
            ax.legend(fontsize=8, ncol=2)
        save(fig, "resource_pressure_trust.png")

        # 4. Attack/scenario-to-component observed penalty heatmap (evaluation only).
        labels = sorted({str(r["scenario_label"]) for r in self.rows})
        components = ["behavior_penalty_observed", "context_penalty_observed", "history_penalty_observed", "risk_elevation_observed"]
        matrix = []
        for label in labels:
            selected = [r for r in self.rows if str(r["scenario_label"]) == label]
            matrix.append([float(np.mean([r[key] for r in selected])) for key in components])
        fig, ax = plt.subplots(figsize=(9, max(3.5, len(labels) * 0.7)))
        image = ax.imshow(np.asarray(matrix), aspect="auto", vmin=0, vmax=1)
        ax.set_xticks(range(len(components)), ["Behavior deficit", "Context deficit", "History deficit", "Risk level"])
        ax.set_yticks(range(len(labels)), labels)
        ax.set_title("Observed component changes by scenario (diagnostic, not causal proof)")
        for i, row in enumerate(matrix):
            for j, value in enumerate(row):
                ax.text(j, i, f"{value:.2f}", ha="center", va="center", fontsize=9)
        fig.colorbar(image, ax=ax, label="Mean score / deficit (0–1)")
        save(fig, "scenario_component_heatmap.png")

        print("\n[VISUALIZER] Saved experiment outputs:")
        for name, path in paths.items():
            print(f"  {name}: {path}")
        return paths
