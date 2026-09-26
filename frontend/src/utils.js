export const STAGES = [
  "Benign",
  "Reconnaissance",
  "Initial Access",
  "Lateral Movement",
  "C2",
  "Exfiltration",
];

export const DEFAULT_FEAT_ORDER = [
  "flow_duration",
  "tot_fwd_pkts",
  "tot_bwd_pkts",
  "fwd_pkt_len_mean",
  "bwd_pkt_len_mean",
  "flow_bytes_s",
  "flow_pkts_s",
  "flow_iat_mean",
  "flow_iat_std",
  "fwd_iat_mean",
  "bwd_iat_mean",
  "syn_flag_cnt",
  "ack_flag_cnt",
  "fin_flag_cnt",
  "rst_flag_cnt",
  "psh_flag_cnt",
  "urg_flag_cnt",
  "down_up_ratio",
  "pkt_size_avg",
  "ttl_variance",
  "tcp_win_size",
  "retransmit_cnt",
];

export function stageIndex(stage) {
  const i = STAGES.indexOf(stage);
  return i >= 0 ? i : 0;
}

export function stageClass(stage) {
  const map = {
    Benign: "benign",
    Reconnaissance: "reconnaissance",
    "Initial Access": "initial-access",
    "Lateral Movement": "lateral-movement",
    C2: "c2",
    Exfiltration: "exfiltration",
  };
  return map[stage] || "benign";
}

export const FEATURE_LABELS = {
  retransmit_cnt: "TCP Retransmissions",
  syn_flag_cnt: "SYN Flag Count",
  ack_flag_cnt: "ACK Flag Count",
  fin_flag_cnt: "FIN Flag Count",
  rst_flag_cnt: "RST Flag Count",
  psh_flag_cnt: "PSH Flag Count",
  urg_flag_cnt: "URG Flag Count",
  tcp_win_size: "TCP Window Size",
  fwd_pkt_len_mean: "Mean Fwd Packet Length",
  bwd_pkt_len_mean: "Mean Bwd Packet Length",
  flow_bytes_s: "Data Rate (Bytes/s)",
  flow_pkts_s: "Packet Rate (Pkts/s)",
  flow_duration: "Connection Duration",
  flow_iat_mean: "Mean Inter-Arrival Time",
  flow_iat_std: "Inter-Arrival Time Variance",
  fwd_iat_mean: "Fwd Inter-Arrival Time",
  bwd_iat_mean: "Bwd Inter-Arrival Time",
  pkt_size_avg: "Average Packet Size",
  ttl_variance: "IP TTL Variance",
  tot_fwd_pkts: "Forward Packets Total",
  tot_bwd_pkts: "Backward Packets Total",
  down_up_ratio: "Down / Up Ratio",
  n_flows: "Flows per Minute",
  n_uniq_src_ip: "Unique Source Hosts",
  n_uniq_dst_ip: "Unique Target Hosts",
  n_uniq_dst_port: "Unique Target Ports",
  n_new_conn_rate: "New Connections / sec",
  f_syn_ratio: "SYN Flag Share",
  f_rst_ratio: "RST Flag Share",
  f_small_flow_frac: "Micro-Flow Fraction",
  n_ent_dst_port: "Port Entropy (Bits)",
  n_dport_per_src_max: "Max Ports per Source",
  f_total_bytes: "Total Transferred Bytes",
};

export function formatFeatureName(key) {
  if (!key) return "";
  return (
    FEATURE_LABELS[key] ||
    key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
  );
}

export function stageColor(stage) {
  const map = {
    Benign: "#58A668",
    Reconnaissance: "#5294E2",
    "Initial Access": "#D6B36A",
    "Lateral Movement": "#DE934B",
    C2: "#D1643F",
    Exfiltration: "#C94A45",
  };
  return map[stage] || "#B8B0A3";
}

export function isAttackFlow(flow) {
  if (!flow) return false;
  if (typeof flow.is_alert === "boolean") return flow.is_alert;
  const prob =
    flow.infiltration_prob ??
    flow.infiltration_probability ??
    flow.latest_risk_score ??
    0;
  const stage = flow.predicted_stage ?? flow.latest_stage;
  return prob > 0.5 || (!!stage && stage !== "Benign");
}

export function severityClass(prob) {
  if (prob >= 0.8) return "critical";
  if (prob >= 0.6) return "high";
  if (prob >= 0.5) return "medium";
  return "low";
}

export function formatTime(isoString) {
  if (!isoString) return "\u2014";
  const d = new Date(isoString);
  return d.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatDateTime(isoString) {
  if (!isoString) return "\u2014";
  const d = new Date(isoString);
  return d.toLocaleString("en-GB", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatProb(p) {
  if (p == null) return "\u2014";
  return (p * 100).toFixed(1) + "%";
}

export function formatBytes(bytes) {
  if (bytes == null) return "\u2014";
  if (bytes < 1024) return bytes.toFixed(0) + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

export function formatDuration(us) {
  if (us == null) return "\u2014";
  const ms = us / 1000;
  if (ms < 1000) return ms.toFixed(0) + "ms";
  if (ms < 60000) return (ms / 1000).toFixed(1) + "s";
  return (ms / 60000).toFixed(1) + "m";
}
