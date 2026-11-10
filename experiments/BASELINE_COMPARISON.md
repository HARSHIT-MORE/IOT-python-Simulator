# Controlled Baseline Comparison

## Run it

From the simulator repository root:

    python experiments/compare_baselines.py

The script creates experiments/results/baseline_comparison/ with:

- comparison_rounds.csv: one row per reading, with its evaluation label, both detector outputs, and trust scores.
- comparison_metrics.json: detection metrics, trust means, and local CPU/memory microbenchmark measurements.
- detector_metrics.png: fixed-step versus rate-aware detector metrics.
- trust_weight_comparison.png: static versus adaptive trust scores for normal and injected-attack readings.

## The detection dataset

The evaluation uses one deterministic dataset containing 150 different readings: 75 unique temperature values and 75 unique HC-SR04 distance values. It includes 22 labeled injected changes and 128 normal readings. The generator uses a fixed seed so rerunning the script recreates the same input data.

There is no tenfold repetition in the detection metrics. Each of the 150 readings is evaluated once by each detector. Labels are evaluation metadata only; the detector and trust calculations do not receive them.

The dataset is synthetic, not captured from Wokwi or physical sensors. It includes gradual sensor variation, rapid injected changes, larger injected steps, returns to baseline, and one benign rapid temperature change.

## Methods compared

1. Fixed-step threshold: flags a reading only when its absolute change from the previous reading exceeds the configured maximum step. It does not account for elapsed time.
2. Device and elapsed-time-aware detector: uses the project's DeviceAttackDetector, with sensor-specific checks and rate limits.
3. Static versus adaptive trust weighting: compares fixed weights with the project's AdaptiveWeightEngine. Static trust uses evidence from the fixed-threshold detector; adaptive trust uses evidence from DeviceAttackDetector. Context and history are held at 1.0 to isolate the weighting effect, and risk follows each method's behavior penalty.

This is a focused detector and trust-weight ablation, not a complete replay of every live simulator component.

## Results from the current dataset

| Measure | Fixed-step threshold | Device/time-aware detector |
|---|---:|---:|
| True positives | 10 | 22 |
| True negatives | 128 | 127 |
| False positives | 0 | 1 |
| False negatives | 12 | 0 |
| Precision | 100% | 95.65% |
| Recall | 45.45% | 100% |
| F1 | 62.50% | 97.78% |
| False positive rate | 0% | 0.78% |

The time-aware detector caught the 12 injected changes that were too small for the fixed step threshold but changed rapidly. It also flagged the one benign rapid environmental change. That is an anomaly alert, not proof of an attack.

Mean trust on normal readings was 1.0000 with static weights and 0.9987 with adaptive weights. On injected-attack readings, the means were 0.9318 and 0.8310, respectively.

## Resource microbenchmark

The dataset remains 150 readings for detection and trust metrics. Separately, the script replays the same dataset 100 times per pipeline solely to stabilize timing and peak-allocation measurements. Those timing repetitions are not added to the detection sample count.

| Measure | Fixed/static pipeline | Rate-aware/adaptive pipeline |
|---|---:|---:|
| Wall time per 1,000 readings | 1.7047 ms | 17.6639 ms |
| Process CPU time per 1,000 readings | 1.0417 ms | 17.7083 ms |
| Peak traced Python allocations | 1,324 bytes | 28,396 bytes |

These measurements cover only the isolated Python comparison components on the computer used to run the script. Traced allocations are not total process RAM. The results do not measure the complete simulator, ESP32 energy use, or physical hardware performance.

## Limits before using results in a paper

The reading profiles and labels are synthetic and hand-authored. The thresholds were not learned or calibrated from a measured dataset. Treat these results as a reproducible pilot, not evidence of real-world performance. For paper-quality claims, collect measured normal and attack traces, define labels independently, calibrate thresholds on separate training data, and evaluate on held-out traces. Measure the full system on the target hardware before claiming system-level resource savings.

