"""Controlled baseline comparison for the temperature and HC-SR04 pipeline.

Run from the repository root:
    python experiments/compare_baselines.py

Ground-truth labels are evaluation metadata only. They are never passed to
DeviceAttackDetector or either trust calculation. The replay compares:
  1. fixed per-sample step thresholds (baseline detector)
  2. the project's elapsed-time/device-type-aware DeviceAttackDetector
  3. fixed versus evidence-adaptive trust weights on the same replay samples

The deterministic profiles are controlled synthetic inputs, not live Wokwi
measurements. Calibrate them with measured normal traces before paper claims.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security.device_attack_detector import DeviceAttackDetector
from gateway.adaptive_weight_engine import AdaptiveWeightEngine


REPLAY_RUNS = 1
REPLAY_SAMPLES_PER_DEVICE = 75
TRUST_WEIGHTS_STATIC = {
    "behavior_weight": 0.25,
    "context_weight": 0.20,
    "history_weight": 0.30,
    "risk_weight": 0.25,
}
CONTEXT_SCORE = 1.0
HISTORY_SCORE = 1.0


def build_profiles() -> dict[str, dict[str, Any]]:
    """Build one deterministic 150-reading synthetic dataset with varying values."""
    import random

    rng = random.Random(20261109)
    specs = {
        "temperature_sensor": {
            "device_id": "TEMP_001",
            "value_key": "temperature",
            "unit": "C",
            "max_step": DeviceAttackDetector.TEMPERATURE_LIMITS[
                "temperature_sensor"
            ]["max_change_c"],
            "base": 24.0,
            "drift": 0.20,
            "attack_jumps": {
                12: 4.4, 24: -4.2, 36: 8.0, 48: -6.5, 60: 4.8,
            },
            "benign_change_index": 70,
        },
        "ultrasonic_distance_sensor": {
            "device_id": "DISTANCE_001",
            "value_key": "distance_cm",
            "unit": "cm",
            "max_step": DeviceAttackDetector.DISTANCE_LIMITS[
                "ultrasonic_distance_sensor"
            ]["max_change_cm"],
            "base": 150.0,
            "drift": 1.0,
            "attack_jumps": {
                10: 18.0, 22: -24.0, 34: 70.0, 46: -65.0, 58: 32.0, 70: 80.0,
            },
            "benign_change_index": None,
        },
    }

    profiles: dict[str, dict[str, Any]] = {}
    for device_type, spec in specs.items():
        baseline = spec["base"]
        elapsed = 0.0
        samples = []
        used_values = set()
        attack_indices = spec["attack_jumps"]
        return_indices = {index + 1 for index in attack_indices}

        for index in range(REPLAY_SAMPLES_PER_DEVICE):
            if index in attack_indices:
                elapsed += 0.1
                value = baseline + attack_indices[index]
                is_attack = True
                scenario = (
                    "injected_large_step"
                    if abs(attack_indices[index]) > spec["max_step"]
                    else "injected_rapid_subthreshold_change"
                )
            elif index in return_indices:
                elapsed += 0.1
                value = baseline
                is_attack = True
                scenario = "injected_return_to_baseline"
            elif index == spec["benign_change_index"]:
                elapsed += 1.0
                baseline += 4.2
                value = baseline
                is_attack = False
                scenario = "benign_rapid_environment_change"
            else:
                elapsed += 5.0
                baseline += rng.uniform(-spec["drift"], spec["drift"])
                value = baseline
                is_attack = False
                scenario = "normal_sensor_variation"

            value = round(value, 2)
            while value in used_values:
                value = round(value + 0.01, 2)
            used_values.add(value)
            samples.append(
                (elapsed, value, is_attack, scenario)
            )

        profiles[device_type] = {
            "device_id": spec["device_id"],
            "value_key": spec["value_key"],
            "unit": spec["unit"],
            "max_step": spec["max_step"],
            "samples": samples,
        }
    return profiles


PROFILES = build_profiles()


CSV_FIELDS = [
    "trace_id", "round", "device_id", "device_type", "scenario",
    "ground_truth_attack", "elapsed_seconds", "value", "unit",
    "fixed_threshold_detected", "adaptive_detector_detected",
    "adaptive_detector_indicators", "behavior_score", "risk_score",
    "static_weight_trust", "adaptive_weight_trust",
]


def confusion_metrics(labels: list[bool], predictions: list[bool]) -> dict[str, Any]:
    tp = sum(actual and predicted for actual, predicted in zip(labels, predictions))
    tn = sum(not actual and not predicted for actual, predicted in zip(labels, predictions))
    fp = sum(not actual and predicted for actual, predicted in zip(labels, predictions))
    fn = sum(actual and not predicted for actual, predicted in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }


def trust_score(scores: dict[str, float], weights: dict[str, float]) -> float:
    value = (
        weights["behavior_weight"] * scores["behavior"]
        + weights["context_weight"] * scores["context"]
        + weights["history_weight"] * scores["history"]
        + weights["risk_weight"] * (1.0 - scores["risk"])
    )
    return round(max(0.0, min(1.0, value)), 3)


def measure_pipeline_cost(timing_repeats: int = 100) -> dict[str, Any]:
    """Measure local CPU/wall time and traced peak Python memory separately."""
    import gc
    import time
    import tracemalloc

    total_samples = timing_repeats * sum(
        len(profile["samples"]) for profile in PROFILES.values()
    )

    def replay(method: str) -> None:
        adaptive_engine = AdaptiveWeightEngine()
        for repeat in range(timing_repeats):
            for device_type, profile in PROFILES.items():
                detector = DeviceAttackDetector() if method == "rate_aware_adaptive_weights" else None
                previous_value = None
                episode_epoch = 1_750_000_000 + repeat * 1000
                for elapsed, value, _label, _scenario in profile["samples"]:
                    if method == "fixed_threshold_static_weights":
                        detected = previous_value is not None and abs(value - previous_value) > profile["max_step"]
                        behavior = 0.7 if detected else 1.0
                        scores = {"behavior": behavior, "context": CONTEXT_SCORE,
                                  "history": HISTORY_SCORE, "risk": 1.0 - behavior}
                        trust_score(scores, TRUST_WEIGHTS_STATIC)
                    else:
                        observation = {
                            "device_id": profile["device_id"], "device_type": device_type,
                            "status": "normal",
                            "humidity": 40.0 if device_type == "temperature_sensor" else None,
                            profile["value_key"]: value,
                            "_received_at_epoch": episode_epoch + elapsed,
                        }
                        detection = detector.analyze(observation)
                        behavior = float(detection["behavior_score"])
                        scores = {"behavior": behavior, "context": CONTEXT_SCORE,
                                  "history": HISTORY_SCORE,
                                  "risk": float(detection["penalty_total"])}
                        weights = adaptive_engine.analyze(
                            behavior_score=scores["behavior"],
                            context_score=scores["context"],
                            history_score=scores["history"],
                            risk_score=scores["risk"],
                        )
                        adaptive_weights = {
                            "behavior_weight": weights["behavior_weight"],
                            "context_weight": weights["context_weight"],
                            "history_weight": weights["history_weight"],
                            "risk_weight": weights["risk_weight"],
                        }
                        trust_score(scores, adaptive_weights)
                    previous_value = value

    results: dict[str, Any] = {}
    for method in ("fixed_threshold_static_weights", "rate_aware_adaptive_weights"):
        gc.collect()
        wall_start = time.perf_counter()
        cpu_start = time.process_time()
        replay(method)
        wall_seconds = time.perf_counter() - wall_start
        cpu_seconds = time.process_time() - cpu_start
        gc.collect()
        tracemalloc.start()
        replay(method)
        _current, peak_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        results[method] = {
            "timing_repeats": timing_repeats,
            "observations": total_samples,
            "wall_ms_per_1000_observations": round(wall_seconds * 1000 * 1000 / total_samples, 4),
            "process_cpu_ms_per_1000_observations": round(cpu_seconds * 1000 * 1000 / total_samples, 4),
            "peak_traced_python_memory_bytes": peak_bytes,
        }
    return results



def run_comparison(output_dir: Path | None = None) -> dict[str, Any]:
    output_dir = output_dir or ROOT / "experiments" / "results" / "baseline_comparison"
    output_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    labels: list[bool] = []
    fixed_predictions: list[bool] = []
    adaptive_predictions: list[bool] = []
    static_trust_by_label: dict[bool, list[float]] = {False: [], True: []}
    adaptive_trust_by_label: dict[bool, list[float]] = {False: [], True: []}

    adaptive_engine = AdaptiveWeightEngine()
    for repeat in range(1, REPLAY_RUNS + 1):
        for device_type, profile in PROFILES.items():
            detector = DeviceAttackDetector()
            previous_value: float | None = None
            episode_epoch = 1_750_000_000 + (repeat * 1000)

            for round_number, (elapsed, value, is_attack, scenario) in enumerate(
                profile["samples"], start=1
            ):
                fixed_detected = (
                    previous_value is not None
                    and abs(value - previous_value) > profile["max_step"]
                )
                observation = {
                    "device_id": profile["device_id"],
                    "device_type": device_type,
                    "status": "normal",
                    "humidity": 40.0 if device_type == "temperature_sensor" else None,
                    profile["value_key"]: value,
                    "_received_at_epoch": episode_epoch + elapsed,
                    "raw_data": {
                        "device_id": profile["device_id"],
                        "device_type": device_type,
                        "status": "normal",
                        "humidity": 40.0 if device_type == "temperature_sensor" else None,
                    profile["value_key"]: value,
                    },
                }

                detection = detector.analyze(observation)
                proposed_detected = bool(detection["anomaly_detected"])
                behavior = float(detection["behavior_score"])
                scores = {
                    "behavior": behavior,
                    "context": CONTEXT_SCORE,
                    "history": HISTORY_SCORE,
                    "risk": float(detection["penalty_total"]),
                }

                adaptive_result = adaptive_engine.analyze(
                    behavior_score=scores["behavior"],
                    context_score=scores["context"],
                    history_score=scores["history"],
                    risk_score=scores["risk"],
                )
                adaptive_weights = {
                    "behavior_weight": adaptive_result["behavior_weight"],
                    "context_weight": adaptive_result["context_weight"],
                    "history_weight": adaptive_result["history_weight"],
                    "risk_weight": adaptive_result["risk_weight"],
                }
                fixed_behavior = 0.7 if fixed_detected else 1.0
                fixed_scores = {
                    "behavior": fixed_behavior,
                    "context": CONTEXT_SCORE,
                    "history": HISTORY_SCORE,
                    "risk": 1.0 - fixed_behavior,
                }
                static_trust = trust_score(fixed_scores, TRUST_WEIGHTS_STATIC)
                adaptive_trust = trust_score(scores, adaptive_weights)

                labels.append(bool(is_attack))
                fixed_predictions.append(bool(fixed_detected))
                adaptive_predictions.append(proposed_detected)
                static_trust_by_label[bool(is_attack)].append(static_trust)
                adaptive_trust_by_label[bool(is_attack)].append(adaptive_trust)
                rows.append({
                    "trace_id": "controlled_synthetic_v1",
                    "round": round_number,
                    "device_id": observation["device_id"],
                    "device_type": device_type,
                    "scenario": scenario,
                    "ground_truth_attack": bool(is_attack),
                    "elapsed_seconds": elapsed,
                    "value": value,
                    "unit": profile["unit"],
                    "fixed_threshold_detected": bool(fixed_detected),
                    "adaptive_detector_detected": proposed_detected,
                    "adaptive_detector_indicators": json.dumps(
                        detection["indicators"], sort_keys=True
                    ),
                    "behavior_score": behavior,
                    "risk_score": scores["risk"],
                    "static_weight_trust": static_trust,
                    "adaptive_weight_trust": adaptive_trust,
                })
                previous_value = value

    resource_cost = measure_pipeline_cost()
    metrics = {
        "protocol": {
            "name": "Controlled sensor replay, detector and trust-weight ablation",
            "replay_runs": REPLAY_RUNS,
            "device_types": list(PROFILES),
            "unique_readings_per_device": REPLAY_SAMPLES_PER_DEVICE,
            "random_seed": 20261109,
            "samples": len(rows),
            "attack_samples": sum(labels),
            "normal_samples": len(labels) - sum(labels),
            "label_usage": (
                "Labels are evaluation-only metadata. They are not passed to "
                "the detector or trust calculations."
            ),
            "trust_inputs": (
                "Static weights use fixed-threshold behavior evidence; adaptive weights use "
                "DeviceAttackDetector behavior evidence. Context/history held at 1.0; risk is "
                "each pipeline's observed behavior penalty."
            ),
            "limits": (
                "Synthetic controlled profiles for temperature and distance only. "
                "This does not establish live Wokwi performance, full-system "
                "resource savings, or generalization to real deployments."
            ),
        },
        "resource_cost_microbenchmark": resource_cost,
        "detection_metrics": {
            "fixed_step_threshold": confusion_metrics(labels, fixed_predictions),
            "device_type_and_elapsed_time_aware_detector": confusion_metrics(
                labels, adaptive_predictions
            ),
        },
        "trust_means": {
            "static_weights": {
                "normal": round(sum(static_trust_by_label[False]) / max(1, len(static_trust_by_label[False])), 4),
                "injected_attack": round(sum(static_trust_by_label[True]) / max(1, len(static_trust_by_label[True])), 4),
                "normal_to_attack_drop": round(
                    sum(static_trust_by_label[False]) / max(1, len(static_trust_by_label[False]))
                    - sum(static_trust_by_label[True]) / max(1, len(static_trust_by_label[True])),
                    4,
                ),
            },
            "adaptive_weights": {
                "normal": round(sum(adaptive_trust_by_label[False]) / max(1, len(adaptive_trust_by_label[False])), 4),
                "injected_attack": round(sum(adaptive_trust_by_label[True]) / max(1, len(adaptive_trust_by_label[True])), 4),
                "normal_to_attack_drop": round(
                    sum(adaptive_trust_by_label[False]) / max(1, len(adaptive_trust_by_label[False]))
                    - sum(adaptive_trust_by_label[True]) / max(1, len(adaptive_trust_by_label[True])),
                    4,
                ),
            },
        },
    }

    csv_path = output_dir / "comparison_rounds.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    json_path = output_dir / "comparison_metrics.json"
    json_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    plot_path = None
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        detector_metrics = metrics["detection_metrics"]
        names = ["Precision", "Recall", "F1", "False positive rate"]
        baseline = detector_metrics["fixed_step_threshold"]
        proposed = detector_metrics["device_type_and_elapsed_time_aware_detector"]
        x = list(range(len(names)))
        width = 0.36
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.bar([i - width / 2 for i in x], [baseline[k] for k in (
            "precision", "recall", "f1", "false_positive_rate"
        )], width, label="Fixed step threshold")
        ax.bar([i + width / 2 for i in x], [proposed[k] for k in (
            "precision", "recall", "f1", "false_positive_rate"
        )], width, label="Device/time-aware detector")
        ax.set_xticks(x, names)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Score")
        ax.set_title("Controlled replay: detector comparison")
        ax.grid(axis="y", alpha=0.25)
        ax.legend()
        fig.tight_layout()
        plot_path = output_dir / "detector_metrics.png"
        fig.savefig(plot_path, dpi=160, bbox_inches="tight")
        plt.close(fig)

        trust = metrics["trust_means"]
        labels_for_trust = ["Normal", "Injected attack"]
        static_values = [
            trust["static_weights"]["normal"],
            trust["static_weights"]["injected_attack"],
        ]
        adaptive_values = [
            trust["adaptive_weights"]["normal"],
            trust["adaptive_weights"]["injected_attack"],
        ]
        x = list(range(len(labels_for_trust)))
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.bar([i - width / 2 for i in x], static_values, width, label="Static weights")
        ax.bar([i + width / 2 for i in x], adaptive_values, width, label="Adaptive weights")
        ax.set_xticks(x, labels_for_trust)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("Mean trust score")
        ax.set_title("Controlled replay: trust weighting comparison")
        ax.grid(axis="y", alpha=0.25)
        ax.legend()
        fig.tight_layout()
        trust_plot_path = output_dir / "trust_weight_comparison.png"
        fig.savefig(trust_plot_path, dpi=160, bbox_inches="tight")
        plt.close(fig)
    except ImportError:
        pass

    result = {
        "csv": str(csv_path),
        "metrics": str(json_path),
        "plot": str(plot_path) if plot_path else None,
        "trust_plot": str(trust_plot_path) if trust_plot_path else None,
        "summary": metrics,
    }
    print(f"Saved per-reading results: {csv_path}")
    print(f"Saved metric summary:      {json_path}")
    if plot_path:
        print(f"Saved detector chart:      {plot_path}")
    print(json.dumps(metrics["detection_metrics"], indent=2))
    print(json.dumps(metrics["trust_means"], indent=2))
    print(json.dumps(metrics["resource_cost_microbenchmark"], indent=2))
    return result


if __name__ == "__main__":
    run_comparison()









