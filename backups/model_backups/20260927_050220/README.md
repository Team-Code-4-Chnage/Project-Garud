# Model backup — 2026-09-27 05:02:20

Snapshot of both shipped model artifact directories, taken before any retraining in response to a
request to verify/improve F1. Restore by copying these back over backend/artifacts/ and
backend/artifacts_v3/ respectively.

- artifacts/       V1 per-flow world model (backend/artifacts/world_model.pt + config.json + scaler.pkl)
- artifacts_v3/     V3 network-state world model (backend/artifacts_v3/network_world_model.pt + config.json)
