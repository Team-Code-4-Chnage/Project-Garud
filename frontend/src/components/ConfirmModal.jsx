import { AlertTriangle, Info, Check, X } from "lucide-react";

export default function ConfirmModal({
  isOpen,
  title = "CONFIRM OPERATION",
  message,
  confirmLabel = "CONFIRM",
  cancelLabel = "CANCEL",
  isDestructive = false,
  isAlert = false,
  onConfirm,
  onCancel,
}) {
  if (!isOpen) return null;

  return (
    <div
      className="garud-drawer-backdrop"
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: "16px",
      }}
      onClick={onCancel}
    >
      <div
        className="garud-card"
        style={{
          width: "100%",
          maxWidth: "460px",
          boxShadow: "var(--shadow-popover)",
          border: `1px solid ${isDestructive ? "var(--danger-border)" : "var(--border-strong)"}`,
          background: "var(--bg-popover)",
          padding: 0,
        }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-modal-title"
      >
        <div
          className="garud-card-header"
          style={{
            padding: "12px 16px",
            borderBottom: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {isDestructive ? (
              <AlertTriangle size={16} color="var(--danger)" />
            ) : (
              <Info size={16} color="var(--accent)" />
            )}
            <h3
              id="confirm-modal-title"
              style={{
                fontFamily: "var(--font-heading)",
                fontSize: "14px",
                fontWeight: 700,
                letterSpacing: "0.06em",
                color: isDestructive ? "var(--danger)" : "var(--text-primary)",
                margin: 0,
                textTransform: "uppercase",
              }}
            >
              {title}
            </h3>
          </div>
          <button
            onClick={onCancel}
            style={{
              background: "none",
              border: "none",
              color: "var(--text-muted)",
              cursor: "pointer",
              padding: "4px",
              display: "flex",
            }}
            aria-label="Close modal"
          >
            <X size={15} />
          </button>
        </div>

        <div style={{ padding: "16px", fontSize: "13px", color: "var(--text-secondary)", lineHeight: 1.5 }}>
          {message}
        </div>

        <div
          style={{
            padding: "10px 16px 14px",
            borderTop: "1px solid var(--border-subtle)",
            display: "flex",
            justifyContent: "flex-end",
            gap: "10px",
          }}
        >
          {!isAlert && (
            <button
              className="garud-btn garud-btn-sm"
              onClick={onCancel}
              style={{ padding: "6px 14px" }}
            >
              {cancelLabel}
            </button>
          )}
          <button
            className={`garud-btn garud-btn-sm ${isDestructive ? "garud-btn-danger" : "garud-btn-primary"}`}
            onClick={onConfirm}
            style={{
              padding: "6px 16px",
              background: isDestructive ? "var(--danger)" : "var(--accent)",
              color: isDestructive ? "#FFFFFF" : "#020E0F",
              fontWeight: 700,
            }}
          >
            {isDestructive ? <AlertTriangle size={13} /> : <Check size={13} />}
            <span>{confirmLabel}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
