"""
Pydantic request/response schemas.
Every endpoint has explicit types — no untyped dicts flying around.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import (
    DEFAULT_K_STEPS,
    DEFAULT_MC_SAMPLES,
    FLOW_FEATURES,
    N_FEATURES,
    WINDOW_SIZE,
)


class FlowRecord(BaseModel):
    """A single network flow with all 22 CIC-IDS features + optional metadata."""
    flow_duration: float
    tot_fwd_pkts: float
    tot_bwd_pkts: float
    fwd_pkt_len_mean: float
    bwd_pkt_len_mean: float
    flow_bytes_s: float
    flow_pkts_s: float
    flow_iat_mean: float
    flow_iat_std: float
    fwd_iat_mean: float
    bwd_iat_mean: float
    syn_flag_cnt: float
    ack_flag_cnt: float
    fin_flag_cnt: float
    rst_flag_cnt: float
    psh_flag_cnt: float
    urg_flag_cnt: float
    down_up_ratio: float
    pkt_size_avg: float
    ttl_variance: float
    tcp_win_size: float
    retransmit_cnt: float

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    process_name: Optional[str] = None
    app_name: Optional[str] = None
    direction: Optional[str] = None
    src_identity: Optional[str] = None
    dst_identity: Optional[str] = None
    timestamp: Optional[datetime] = None
    source: Optional[str] = Field(
        default="api",
        description='Origin of this flow: "live_capture", "simulated", "csv_upload", or "api"',
    )
    heartbleed_signature: Optional[bool] = Field(
        default=False,
        description="Set by capture/pcap ingestion when a deterministic CVE-2014-0160 "
                     "malformed-heartbeat wire signature was found in this flow's packets. "
                     "Not one of the 22 ML features — triggers an immediate rule-based alert.",
    )
    stage: Optional[str] = Field(
        default=None,
        description="Kill chain attack stage (e.g. Reconnaissance, Initial Access, Lateral Movement, C2, Exfiltration, Benign)",
    )
    attack_type: Optional[str] = Field(
        default=None,
        description="Specific attack technique / label (e.g. PortScan, BruteForce, DoS, DDoS, Bot, Infiltration)",
    )

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate IPv4 / IPv6 addresses while safely permitting legitimate
        telemetry placeholder tokens ('unknown', 'localhost', '?', None).
        """
        if v is None:
            return None
        val = str(v).strip()
        if not val:
            return None
        if val.lower() in ("unknown", "?", "—", "-", "none", "null", "localhost", "broadcast"):
            return val

        if val.startswith("[") and "]" in val:
            val = val[1:val.index("]")]
        elif ":" in val and val.count(":") == 1:
            val = val.split(":")[0]

        try:
            ipaddress.ip_address(val)
        except ValueError:
            raise ValueError(
                f"Invalid IP address format: '{val}'. Must be a valid IPv4, IPv6, "
                f"or supported placeholder ('unknown', 'localhost')."
            )
        return val

    def to_feature_array(self) -> list[float]:
        """Extract the 22 features in the correct order."""
        return [getattr(self, f) for f in FLOW_FEATURES]


class PredictRequest(BaseModel):
    """A window of 6 flow records for single-step prediction."""
    window: list[list[float]] = Field(
        ..., description=f"A {WINDOW_SIZE}x{N_FEATURES} matrix of feature values"
    )
    needs_scaling: bool = Field(
        default=False, description="Whether raw features should be scaled before inference"
    )

    @field_validator("window")
    @classmethod
    def validate_window(cls, v):
        if len(v) != WINDOW_SIZE:
            raise ValueError(f"Window must have exactly {WINDOW_SIZE} rows, got {len(v)}")
        for i, row in enumerate(v):
            if len(row) != N_FEATURES:
                raise ValueError(
                    f"Row {i} has {len(row)} features, expected {N_FEATURES}"
                )
            for j, val in enumerate(row):
                if not isinstance(val, (int, float)):
                    raise ValueError(f"Row {i}, feature {j} is not numeric: {val}")
        return v


class PredictResponse(BaseModel):
    infiltration_probability: float = Field(..., ge=0.0, le=1.0)
    predicted_stage: str
    predicted_stage_id: int
    is_alert: bool
    threshold: float


class ForecastRequest(BaseModel):
    window: list[list[float]]
    k_steps: int = Field(default=DEFAULT_K_STEPS, ge=1, le=20)
    n_mc_samples: int = Field(default=DEFAULT_MC_SAMPLES, ge=1, le=100)
    needs_scaling: bool = Field(
        default=False, description="Whether raw features should be scaled before inference"
    )

    @field_validator("window")
    @classmethod
    def validate_window(cls, v):
        if len(v) != WINDOW_SIZE:
            raise ValueError(f"Window must have exactly {WINDOW_SIZE} rows, got {len(v)}")
        for i, row in enumerate(v):
            if len(row) != N_FEATURES:
                raise ValueError(f"Row {i} has {len(row)} features, expected {N_FEATURES}")
        return v


class ForecastStep(BaseModel):
    step: int
    infiltration_prob_mean: float
    infiltration_prob_std: float
    infiltration_prob_ema: float
    predicted_stage: str


class ForecastResponse(BaseModel):
    steps: list[ForecastStep]
    threshold: float
    alert_triggered: bool
    alert_at_step: Optional[int] = None


class ExplainRequest(BaseModel):
    window: list[list[float]]
    top_k: int = Field(default=10, ge=1, le=22)
    needs_scaling: bool = Field(
        default=False, description="Whether raw features should be scaled before inference"
    )
    method: str = Field(
        default="shap", description="Attribution method: 'shap' or 'gradient'"
    )

    @field_validator("window")
    @classmethod
    def validate_window(cls, v):
        if len(v) != WINDOW_SIZE:
            raise ValueError(f"Window must have exactly {WINDOW_SIZE} rows, got {len(v)}")
        for i, row in enumerate(v):
            if len(row) != N_FEATURES:
                raise ValueError(f"Row {i} has {len(row)} features, expected {N_FEATURES}")
        return v


class FeatureAttribution(BaseModel):
    feature: str
    importance: float
    direction: str
    delta: Optional[float] = None


class ExplainResponse(BaseModel):
    attributions: list[FeatureAttribution]
    infiltration_probability: float
    predicted_stage: str
    method_used: str = "shap"
    temporal_weights: Optional[list[float]] = None


class AlertOut(BaseModel):
    id: int
    session_key: str
    severity: str
    infiltration_prob: float
    predicted_stage: str
    recommended_action: str
    created_at: datetime
    acknowledged: bool

    # Proactive Cyber Defense (SIH 2026 PS:26153)
    mitigated: bool = False
    mitigation_action: Optional[str] = None
    mitigation_rule: Optional[str] = None
    mitigated_at: Optional[datetime] = None

    # Blockchain Cryptographic Audit Ledger (SIH 2026 PS:26153)
    block_hash: Optional[str] = None
    prev_hash: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ContainmentRequest(BaseModel):
    action: str = Field(
        default="auto",
        description="Containment action: 'block_src', 'isolate_host', 'block_outbound', 'auto'",
    )


class ContainmentRuleOut(BaseModel):
    alert_id: int
    session_key: str
    action: str
    rule_type: str
    rule_command: str
    enforced_at: datetime
    status: str = "enforced"


class LedgerVerificationOut(BaseModel):
    status: str
    chain_intact: bool
    total_blocks: int
    genesis_hash: Optional[str] = None
    head_hash: Optional[str] = None
    tampered_at_block: Optional[int] = None
    verified_at: datetime


class SingleFlowIngestResponse(BaseModel):
    session_key: str
    buffer_size: int
    prediction: Optional[dict] = None
    alert: Optional[dict] = None
    heartbleed_alert: Optional[dict] = None


class IngestResponse(BaseModel):
    flows_accepted: int
    flows_rejected: int
    errors: list[str]
    alerts_generated: int
    input_kind: Optional[str] = None
    rows_read: Optional[int] = None
    schema_report: Optional[dict] = Field(default=None, alias="schema")
    evaluation: Optional[dict] = None
    label_counts: Optional[dict] = None

    model_config = {"populate_by_name": True}


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    db_connected: bool
    artifacts_path: str
    features_count: int
    features: list[str]
    stages: list[str]
    device: str
    system_mode: Optional[str] = "live"
    model_version: Optional[str] = "1.0.0"
    model_hash: Optional[str] = None
    scaler_hash: Optional[str] = None
    hidden_size: Optional[int] = None
    num_layers: Optional[int] = None
    dropout: Optional[float] = None
    window_size: Optional[int] = None


