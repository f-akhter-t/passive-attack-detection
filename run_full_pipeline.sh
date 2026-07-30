#!/usr/bin/env bash
# ============================================================================
# run_full_pipeline.sh
#
# Reproduces Phases 1-7 of the masterplan end-to-end, using the already-
# patched scripts/extract_features.py, scripts/plot_results.py, and
# scripts/evaluate.py (confirmed patched via `ls -la scripts/` timestamps).
#
# Run this from INSIDE the passive-attack-detection project root, i.e.:
#   cd /media/sf_shared_Kali/passive-attack-detection
#   bash run_full_pipeline.sh
#
# It will print each phase's output as it goes so you can compare against
# the numbers already shown to you. Stops on first real error (set -e).
# ============================================================================
set -e

bash demo/demo_banner.sh

echo "############################################################"
echo "# Sanity check: confirm the patched scripts are actually here"
echo "############################################################"
for f in scripts/extract_features.py scripts/plot_results.py scripts/evaluate.py scripts/feature_importance.py; do
    if [ ! -f "$f" ]; then
        echo "ERROR: $f not found. Are you running this from the project root?"
        exit 1
    fi
done
grep -q "all_macs" scripts/extract_features.py || { echo "ERROR: extract_features.py doesn't look patched (no 'all_macs' found). Did you overwrite it with the fixed version?"; exit 1; }
grep -q 'unit="s"' scripts/plot_results.py || { echo "ERROR: plot_results.py doesn't look patched (missing unit=\"s\")."; exit 1; }
grep -q -- "--tz" scripts/evaluate.py || { echo "ERROR: evaluate.py doesn't look patched (missing --tz argument)."; exit 1; }
grep -q "Per-device breakdown" scripts/evaluate.py || { echo "ERROR: evaluate.py is missing the per-device breakdown section -- did you copy the latest version?"; exit 1; }
echo "OK: all patched scripts are present."
echo

echo "############################################################"
echo "# Backing up any existing results/models before overwriting"
echo "############################################################"
BACKUP_DIR="results_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
[ -d results ] && cp -r results "$BACKUP_DIR/results_old" 2>/dev/null || true
[ -d models ] && cp -r models "$BACKUP_DIR/models_old" 2>/dev/null || true
echo "Backed up to $BACKUP_DIR/ (if anything existed to back up)."
echo

echo "############################################################"
echo "# Checking required Python packages"
echo "############################################################"
python3 -c "import scapy, pandas, numpy, sklearn, matplotlib, seaborn, joblib" 2>/dev/null && echo "OK: all required packages importable." || {
    echo "Some packages missing -- installing from requirements.txt ..."
    pip install -r requirements.txt --break-system-packages
}
echo

mkdir -p data/baseline data/attack models results results/sweep results/w5 results/plots

echo "############################################################"
echo "# PHASE 1/2 -- Feature extraction with the fixed script"
echo "############################################################"
echo "--- Baseline, 10s window ---"
python3 scripts/extract_features.py --pcap data/baseline/baseline_long.pcap --window 10 --out data/baseline/features_baseline.csv

echo
echo "--- Baseline, 5s window ---"
python3 scripts/extract_features.py --pcap data/baseline/baseline_long.pcap --window 5 --out data/baseline/features_baseline_w5.csv

echo
echo "--- Attack (all pcaps in data/attack/), 10s window ---"
python3 scripts/extract_features.py --pcap data/attack/ --window 10 --out data/attack/features_attack.csv

echo
echo "--- Attack (all pcaps in data/attack/), 5s window ---"
python3 scripts/extract_features.py --pcap data/attack/ --window 5 --out data/attack/features_attack_w5.csv

echo
echo "Quick idle-window / latency-variance sanity check on the 10s baseline:"
python3 -c "
import pandas as pd
df = pd.read_csv('data/baseline/features_baseline.csv')
idle = df[df['pkt_count']==0]
print(f'  Total rows: {len(df)}, idle (zero-filled) rows: {len(idle)} ({100*len(idle)/len(df):.1f}%)')
lat = df.loc[df['avg_response_latency'].notna(), 'avg_response_latency']
print(f'  avg_response_latency: {lat.nunique()} distinct non-null values (should be > 1, not a single repeated constant)')
"
echo

echo "############################################################"
echo "# PHASE 3 -- Train / detect / evaluate at 10s, contamination=0.08"
echo "############################################################"
mkdir -p models/c08_fixed
python3 scripts/train_model.py --features data/baseline/features_baseline.csv --algo isoforest --contamination 0.08 --out models/c08_fixed/
python3 scripts/detect.py --features data/attack/features_attack.csv --model models/c08_fixed/isoforest_model.joblib --scaler models/c08_fixed/scaler.joblib --out results/detections_fixed_c08.csv
python3 scripts/evaluate.py --detections results/detections_fixed_c08.csv --attack-log data/attack/attack_log.csv --out results/evaluation_fixed_c08.txt --tz America/New_York
echo
echo "=== results/evaluation_fixed_c08.txt ==="
cat results/evaluation_fixed_c08.txt
echo

echo "############################################################"
echo "# PHASE 3b -- OCSVM retest (now that the pipeline is fixed)"
echo "############################################################"
mkdir -p models/ocsvm_fixed
python3 scripts/train_model.py --features data/baseline/features_baseline.csv --algo ocsvm --nu 0.05 --out models/ocsvm_fixed/
python3 scripts/detect.py --features data/attack/features_attack.csv --model models/ocsvm_fixed/ocsvm_model.joblib --scaler models/ocsvm_fixed/scaler.joblib --out results/detections_ocsvm_fixed.csv
python3 scripts/evaluate.py --detections results/detections_ocsvm_fixed.csv --attack-log data/attack/attack_log.csv --out results/evaluation_ocsvm_fixed.txt --tz America/New_York
echo

echo "############################################################"
echo "# PHASE 4 -- Feature variance audit (all baseline columns)"
echo "############################################################"
python3 -c "
import pandas as pd
df = pd.read_csv('data/baseline/features_baseline.csv')
feat_cols = [c for c in df.columns if c not in ('window_start','device_mac')]
stats = df[feat_cols].describe().T
stats['std_to_mean'] = (stats['std'] / stats['mean'].abs()).round(3)
stats['near_constant'] = stats['std'].round(6) == 0
pd.set_option('display.width', 200)
print(stats[['mean','std','std_to_mean','near_constant','min','max']].to_string())
"
echo

echo "############################################################"
echo "# PHASE 5 -- Contamination sweep (0.02, 0.05, 0.08, 0.12, 0.20, 0.25, 0.30, 0.35, 0.40), 10s"
echo "############################################################"
for C in 0.02 0.05 0.08 0.12 0.20 0.25 0.30 0.35 0.40; do
  mkdir -p "models/sweep/c_${C}"
  python3 scripts/train_model.py \
      --features data/baseline/features_baseline.csv \
      --algo isoforest \
      --contamination "${C}" \
      --out "models/sweep/c_${C}/" > /dev/null

  python3 scripts/detect.py \
      --features data/attack/features_attack.csv \
      --model "models/sweep/c_${C}/isoforest_model.joblib" \
      --scaler "models/sweep/c_${C}/scaler.joblib" \
      --out "results/sweep/detections_c_${C}.csv" > /dev/null

  python3 scripts/evaluate.py \
      --detections "results/sweep/detections_c_${C}.csv" \
      --attack-log data/attack/attack_log.csv \
      --out "results/sweep/eval_c_${C}.txt" \
      --tz America/New_York > /dev/null

  echo "--- contamination=${C} ---"
  grep -E "Detection rate|False positive rate|Precision" \
      "results/sweep/eval_c_${C}.txt"
  echo
done

echo "############################################################"
echo "# PHASE 6 -- 5s vs 10s window comparison (contamination=0.08)"
echo "############################################################"
mkdir -p models/w5_c08
python3 scripts/train_model.py --features data/baseline/features_baseline_w5.csv --algo isoforest --contamination 0.08 --out models/w5_c08/
python3 scripts/detect.py --features data/attack/features_attack_w5.csv --model models/w5_c08/isoforest_model.joblib --scaler models/w5_c08/scaler.joblib --out results/w5/detections_w5_c08.csv
python3 scripts/evaluate.py --detections results/w5/detections_w5_c08.csv --attack-log data/attack/attack_log.csv --out results/w5/evaluation_w5_c08.txt --tz America/New_York
echo
echo "=== 10s (from Phase 3) vs 5s ==="
echo "--- 10s ---"; grep -E "Detection rate|False positive rate|Precision" results/evaluation_fixed_c08.txt
echo "--- 5s  ---"; grep -E "Detection rate|False positive rate|Precision" results/w5/evaluation_w5_c08.txt
echo

echo "############################################################"
echo "# PHASE 7 -- Wilson CI check (already built into evaluate.py output above)"
echo "############################################################"
grep "95% CI" results/evaluation_fixed_c08.txt
echo

echo "############################################################"
echo "# PHASE 9 -- Feature importance (permutation, AUC-drop)"
echo "############################################################"
python3 scripts/feature_importance.py \
    --features data/attack/features_attack.csv \
    --attack-log data/attack/attack_log.csv \
    --model models/c08_fixed/isoforest_model.joblib \
    --scaler models/c08_fixed/scaler.joblib \
    --feature-cols models/c08_fixed/feature_cols.joblib \
    --out results/feature_importance.txt \
    --tz America/New_York
echo

echo "############################################################"
echo "# Regenerating report figures"
echo "############################################################"
python3 scripts/plot_results.py --features data/baseline/features_baseline.csv \
    --attack-features data/attack/features_attack.csv \
    --detections results/detections_fixed_c08.csv \
    --outdir results/plots/ \
    --tz America/New_York
echo

echo "############################################################"
echo "# DONE. Key outputs to check:"
echo "#   results/evaluation_fixed_c08.txt   (Phase 3 main result)"
echo "#   results/sweep/eval_c_*.txt         (Phase 5 sweep)"
echo "#   results/w5/evaluation_w5_c08.txt   (Phase 6, 5s comparison)"
echo "#   results/plots/*.png                (figures for the report)"
echo "############################################################"
