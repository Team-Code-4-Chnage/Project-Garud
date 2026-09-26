import { useState, useRef } from "react";
import {
  Upload,
  FileText,
  CheckCircle2,
  AlertTriangle,
  FileCode,
} from "lucide-react";
import { apiUpload } from "../api";

export default function UploadPanel() {
  const [result, setResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef(null);

  const handleFile = async (file) => {
    if (!file) return;
    const name = file.name.toLowerCase();
    const isCsv = name.endsWith(".csv");
    const isPcap =
      name.endsWith(".pcap") ||
      name.endsWith(".cap") ||
      name.endsWith(".pcapng");

    if (!isCsv && !isPcap) {
      setResult({
        error:
          "Please upload a CSV (.csv) or PCAP (.pcap, .cap, .pcapng) telemetry capture file.",
      });
      return;
    }

    setUploading(true);
    setResult(null);
    try {
      const endpoint = isPcap ? "/ingest/pcap" : "/ingest/csv";
      const data = await apiUpload(endpoint, file);
      setResult(data);
    } catch (e) {
      setResult({ error: e.message });
    }
    setUploading(false);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  };

  return (
    <>
      <div style={{ marginBottom: "var(--sp-4)" }}>
        <span className="section-label" style={{ fontSize: "0.85rem" }}>
          Ingest Network Telemetry Captures
        </span>
        <p
          className="mono text-sm"
          style={{ color: "var(--text-secondary)", marginTop: "var(--sp-1)" }}
        >
          Ingest <strong>CSV flow telemetry</strong> (22 CIC-IDS temporal
          features) or raw <strong>PCAP packet captures</strong>{" "}
          (.pcap/.pcapng). The engine extracts temporal vectors, builds state
          history, and projects kill-chain evolution.
        </p>
      </div>

      <div
        className={`upload-zone ${dragging ? "dragging" : ""}`}
        onClick={() => fileRef.current?.click()}
        onDrop={onDrop}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
      >
        {uploading ? (
          <>
            <div
              className="loading-spinner"
              style={{ margin: "0 auto var(--sp-3)", width: 28, height: 28 }}
            />
            <p style={{ fontWeight: 700, color: "var(--c-gold)" }}>
              Extracting network features and running inference...
            </p>
            <span
              className="mono text-xs text-muted"
              style={{ display: "block", marginTop: 4 }}
            >
              Computing LSTM state updates
            </span>
          </>
        ) : (
          <>
            <Upload
              size={38}
              className="upload-icon"
              style={{ color: "var(--c-gold)", margin: "0 auto var(--sp-2)" }}
            />
            <p
              style={{
                fontWeight: 700,
                fontSize: "1rem",
                color: "var(--text-primary)",
              }}
            >
              Drop CSV or PCAP Capture File Here, or Click to Browse
            </p>
            <span
              className="mono text-xs text-muted"
              style={{ display: "block", marginTop: 4 }}
            >
              Supported: .csv, .pcap, .cap, .pcapng • Auto-mapped to 22 CIC-IDS
              feature dimensions
            </span>
          </>
        )}
        <input
          ref={fileRef}
          type="file"
          accept=".csv,.pcap,.cap,.pcapng"
          style={{ display: "none" }}
          onChange={(e) => handleFile(e.target.files[0])}
        />
      </div>

      {result && (
        <div className="panel mt-4">
          <div className="panel-header">
            <span className="panel-title">Telemetry Ingestion Results</span>
          </div>
          <div className="panel-body">
            {result.error ? (
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  color: "var(--c-red)",
                  background: "rgba(201, 74, 69, 0.1)",
                  padding: "var(--sp-3)",
                  borderRadius: "var(--radius)",
                  border: "1px solid rgba(201, 74, 69, 0.3)",
                }}
              >
                <AlertTriangle size={18} />
                <span className="mono" style={{ fontWeight: 600 }}>
                  {result.error}
                </span>
              </div>
            ) : (
              <>
                <div
                  className="stats-bar"
                  style={{ marginBottom: "var(--sp-3)" }}
                >
                  <div className="stat-card">
                    <div
                      className="stat-card-label"
                      style={{ color: "var(--severity-low)" }}
                    >
                      Flows Accepted
                    </div>
                    <div
                      className="stat-card-value"
                      style={{ color: "var(--severity-low)" }}
                    >
                      {result.flows_accepted}
                    </div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-card-label">Rejected / Invalid Flows</div>
                    <div
                      className="stat-card-value"
                      style={{
                        color:
                          result.flows_rejected > 0
                            ? "var(--c-red)"
                            : undefined,
                      }}
                    >
                      {result.flows_rejected}
                    </div>
                  </div>
                  <div className="stat-card">
                    <div className="stat-card-label">Security Alerts Triggered</div>
                    <div
                      className="stat-card-value"
                      style={{
                        color:
                          result.alerts_generated > 0
                            ? "var(--c-gold)"
                            : undefined,
                      }}
                    >
                      {result.alerts_generated}
                    </div>
                  </div>
                </div>

                {result.errors?.length > 0 && (
                  <div
                    style={{
                      marginTop: "var(--sp-3)",
                      background: "var(--bg-dark)",
                      padding: "var(--sp-3)",
                      borderRadius: "var(--radius)",
                    }}
                  >
                    <span
                      className="mono text-sm"
                      style={{ color: "var(--c-gold)", fontWeight: 700 }}
                    >
                      Telemetry Parsing Warnings:
                    </span>
                    <ul
                      style={{
                        marginTop: "var(--sp-2)",
                        fontSize: "0.74rem",
                        color: "var(--text-secondary)",
                        fontFamily: "var(--font-mono)",
                        listStyle: "none",
                      }}
                    >
                      {result.errors.slice(0, 10).map((e, i) => (
                        <li key={i} style={{ padding: "2px 0" }}>
                          • {e}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export { UploadPanel as IngestPanel };
