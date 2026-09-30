# Manual Training and Setup

The application runs directly with Python and Node.js.

## Run the Application

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

The backend uses artifacts in `backend/artifacts/` and `backend/artifacts_v3/`. Copy `.env.example` to `.env` when custom artifact, database, API, or frontend paths are needed.

## Retraining

Retraining is explicit and manual:

```text
dataset -> preprocessing -> optional augmentation -> session windows
        -> train/validation/test split -> training -> evaluation
        -> optional calibration -> backend/artifacts/
```

Prepare a flow dataset:

```bash
python data/download_cicids.py
python data/preprocess_cicids.py --input-dir data/raw_cicids --output real_flows.csv
python data/augment_lateral_movement.py --target real_flows.csv
python data/augment_initial_access.py --target real_flows.csv
python data/fix_initial_access_sessions.py --target real_flows.csv
```

Train the per-flow model:

```bash
python pipeline_fixed.py \
  --data real_flows.csv \
  --out backend/artifacts \
  --epochs 20 \
  --batch-size 128 \
  --hidden-size 256 \
  --num-layers 2 \
  --dropout 0.25 \
  --stage-target current
```

The output directory contains `world_model.pt`, `scaler.pkl`, `config.json`, and `benchmark_comparison.csv`. Run `python experiments/calibrate_stage_logits.py` only when recalibrating newly trained weights; review its output before copying any bias into `config.json`.

The network-state model has a separate workflow under `worldmodel_v2/` and `worldmodel_v3/`. Its output is written to `backend/artifacts_v3/` and must be evaluated with the matching network-state tests and experiment scripts.

## Experimentation

Use `experiments/` for offline analysis:

- `evaluate_model.py`: per-flow held-out risk, stage, rollout, and deduplication metrics.
- `calibrate_stage_logits.py`: validation-only stage-logit calibration.
- `family_holdout_eval.py`: attack-family generalization study.
- `pcap_parity.py` and `pcap_model_parity.py`: feature and model-decision parity studies.
- `tune_infiltration_threshold.py`: threshold comparison without changing deployment defaults.
- `worldmodel_v2/evaluate.py`, `worldmodel_v3/run_lodo.py`, and `worldmodel_v3/run_behaviour.py`: network-state studies.

Experiment JSON and CSV files are saved results. They do not trigger retraining or change the running service.

## Tests

```bash
python3 -m pytest backend/tests
cd frontend
npm run lint
npm run build
```
