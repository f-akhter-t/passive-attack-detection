# Passive Attack Detection via Behavioral Network Fingerprinting

**IIUC CSE-4744 — Computer Security Sessional, Capstone Project**
Team RaspberryPies — C223256 Riktika Talukder, C223261 Meheri Monir, C223265 Farhana Akhter Talukder

Signature-free detection of passive and semi-passive network attackers (ARP
sniffing/spoofing) using per-device behavioral fingerprinting and unsupervised
anomaly detection (Isolation Forest / One-Class SVM), trained only on normal
LAN traffic.

## How it works

1. Capture normal ("baseline") and attack-period traffic as pcaps.
2. Extract per-device, per-time-window behavioral features (packet/byte
   counts, inter-arrival timing, ARP request/reply activity, broadcast ratio,
   ICMP response latency, send/receive ratio) — including zero-filled rows
   for idle windows, since silence is itself a signal this project uses.
3. Train an anomaly model (Isolation Forest or One-Class SVM) on baseline
   data only.
4. Score attack-period windows against that model.
5. Evaluate recall, false-positive rate, precision, time-to-detect, and
   per-device attribution, with Wilson confidence intervals throughout.

## Repository structure

```
scripts/                    Core pipeline (see below)
data/baseline/               Baseline capture(s) + extracted features
data/attack/                  Attack-period captures (multiple tools) + extracted
                              features, including attack_log.csv (ground truth)
models/                      Trained models, scalers, feature-cols, and imputation
                              medians, one subfolder per experiment configuration
results/                     Evaluation reports, detection CSVs, and figures
demo/                        Live-demo tooling (separate from the evaluated
                              pipeline above — see demo/README.md)
run_full_pipeline.sh         Runs the entire pipeline end-to-end, phase by phase
traffic_gen_client1.sh
traffic_gen_client2.sh       Generate baseline/normal traffic during capture
evasion_and_passive_tool_tests.sh
client_traffic_for_evasion_tests.sh
                              Attack-side test harness (tcpdump/ettercap/bettercap,
                              including throttled "evasion" variants)
requirements.txt
```

## Scripts (`scripts/`)

| Script | Purpose |
|---|---|
| `extract_features.py` | pcap → per-device, per-window feature CSV |
| `train_model.py` | Fits Isolation Forest or One-Class SVM on baseline features only; saves the model, scaler, feature-column list, and **imputation medians** (all persisted so detection reuses exactly the training-time statistics — no NaNs are ever filled from test data) |
| `detect.py` | Scores a feature CSV against a trained model + scaler, using the persisted imputation medians |
| `evaluate.py` | Detection rate, FPR, precision, time-to-detect per tool, and a per-device breakdown, all with Wilson confidence intervals; timezone-aware matching against `attack_log.csv` |
| `feature_importance.py` | Permutation importance (AUC-drop) against the trained model, using the persisted imputation medians |
| `plot_results.py` | Generates the report figures in `results/plots/` |
| `synthetic_data.py` | Synthetic feature generator, used only for pipeline smoke-testing, not for reported results |

## Running the full pipeline

```
bash run_full_pipeline.sh
```

This runs, in order: feature extraction (10s and 5s windows) → training/detection/evaluation at the default contamination → an OCSVM retest → a feature-variance sanity check → a contamination sweep (0.02–0.40) → the 5s-vs-10s window comparison → permutation feature importance → figure regeneration. All outputs land in `results/` and `models/`.

## Key results (most recent full run)

| Metric | Value |
|---|---|
| Detection rate (recall), 10s window, contamination=0.08 | 25.0% (95% CI 18.9–32.3%, n=156) |
| False positive rate | 0.2% (95% CI 0.1–0.3%, n=5100) |
| Precision | 81.2% |
| Attacker-device recall (per-device breakdown) | 63.5% |
| Client-device recall (per-device breakdown) | 5.8% and 5.8% |
| Feature-importance baseline AUC | 0.9082 |
| Top feature by permutation importance | `mean_iat` (then `arp_reply_rate`, `arp_reply_count`) |
| OCSVM recall / FPR (post-fix, no longer degenerate) | 25.6% / 0.2% |

Full per-tool time-to-detect, the full contamination sweep, and the 5s/10s
comparison are in `results/evaluation_fixed_c08.txt`, `results/sweep/`, and
`results/w5/` respectively.

## Notable findings / limitations

- The purely-passive control tool (tshark) is **not detected during its active
  window** in the latest 10s run; keep that as a stated result, not a claim of
  universal passive-tool detection.
- Throttled ("slow") ettercap/bettercap variants show reduced detection at 10s
  windows, and the 5s comparison is reported separately in `results/w5/`.
- Per-device breakdown confirms the design intent: flags attribute
  disproportionately to the actual attacking device rather than spreading
  evenly across all devices once ARP activity starts on the segment.
- `features_attack.csv` combines multiple capture sessions separated by hours;
  because zero-fill is correct for silence, the file also includes long
  inter-session idle stretches. Treat the all-inclusive FPR/precision as
  session-spanning statistics, not a continuous-background estimate.

## Live demo

See `demo/README.md` — the demo tooling is intentionally kept separate from
the pipeline above so rehearsal captures never mix into the evaluated
dataset or reported numbers.
