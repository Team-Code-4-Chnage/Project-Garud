"""
Configuration and settings for the backend service.
All paths, constants, and tunable parameters live here.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = Path(os.environ.get("ARTIFACTS_DIR", BASE_DIR / "artifacts"))
DB_DIR = Path(os.environ.get("DB_DIR", BASE_DIR / "data"))

MODEL_PATH = ARTIFACTS_DIR / "world_model.pt"
SCALER_PATH = ARTIFACTS_DIR / "scaler.pkl"
CONFIG_PATH = ARTIFACTS_DIR / "config.json"
DATABASE_URL = f"sqlite+aiosqlite:///{DB_DIR / 'forecaster.db'}"

WINDOW_SIZE = 6
N_FEATURES = 22
HIDDEN_SIZE = 256
NUM_LSTM_LAYERS = 2
LSTM_DROPOUT = 0.25
N_STAGES = 6
STAGES = [
    "Benign", "Reconnaissance", "Initial Access",
    "Lateral Movement", "C2", "Exfiltration",
]
STAGE2ID = {s: i for i, s in enumerate(STAGES)}

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]

DEFAULT_THRESHOLD = float(os.environ.get("ALERT_THRESHOLD", "0.5"))
DEFAULT_K_STEPS = 6
DEFAULT_MC_SAMPLES = 20
DEFAULT_MC_NOISE_STD = 0.05
EMA_ALPHA = 0.4

ADAPTIVE_THRESHOLD_ENABLED = os.environ.get("ADAPTIVE_THRESHOLD", "1") == "1"
ADAPTIVE_EMA_ALPHA = 0.3
ADAPTIVE_SIGMA_MULTIPLIER = 2.0

API_KEY = os.environ.get("API_KEY", None)

_extra_origins = [
    url.strip()
    for url in os.environ.get("FRONTEND_URL", "").split(",")
    if url.strip()
]
ALLOWED_ORIGINS = list({
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    *_extra_origins,
})

SESSION_TIME_BUCKET_SECONDS = 300

# A session for one (src_ip, dst_ip) pair continues as long as flows keep arriving within this many
# seconds of the last one seen; only a gap longer than this starts a new session_key. Continuous
# traffic (a long-lived app connection) must not be split into multiple "sessions" just because it
# crossed a fixed wall-clock boundary.
SESSION_IDLE_TIMEOUT_SECONDS = 300
