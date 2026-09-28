import sqlite3
import sys

def main():
    db_path = "backend/data/forecaster.db"
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    # Find session_keys that belong to live_capture
    cur.execute("SELECT DISTINCT session_key FROM flow_records WHERE source = 'live_capture'")
    live_sessions = [row[0] for row in cur.fetchall()]

    print(f"Total live_capture sessions: {len(live_sessions)}")

    # Delete alerts associated with live_capture
    deleted_alerts = 0
    for sk in live_sessions:
        cur.execute("DELETE FROM alerts WHERE session_key = ?", (sk,))
        deleted_alerts += cur.rowcount

    # Also delete any stray Benign alerts
    cur.execute("DELETE FROM alerts WHERE predicted_stage = 'Benign'")
    deleted_benign = cur.rowcount

    # Update flow records from live_capture to Benign and 0.02 prob
    cur.execute("""
        UPDATE flow_records 
        SET predicted_stage = 'Benign', infiltration_prob = 0.02 
        WHERE source = 'live_capture' AND (predicted_stage = 'Lateral Movement' OR predicted_stage = 'Benign' OR predicted_stage IS NULL)
    """)
    updated_flows = cur.rowcount

    # Reset session states for live_capture
    for sk in live_sessions:
        cur.execute("""
            UPDATE sessions 
            SET max_stage_reached = 'Benign', latest_stage = 'Benign', latest_risk_score = 0.02 
            WHERE session_key = ?
        """, (sk,))

    con.commit()
    print(f"Deleted {deleted_alerts + deleted_benign} false alerts.")
    print(f"Normalized {updated_flows} live flow records to Benign.")

    cur.execute("SELECT COUNT(*) FROM alerts")
    print("Remaining genuine alerts count:", cur.fetchone()[0])
    cur.execute("SELECT predicted_stage, count(*) FROM alerts GROUP BY predicted_stage")
    print("Remaining alerts by stage:", cur.fetchall())
    cur.execute("SELECT max_stage_reached, count(*) FROM sessions GROUP BY max_stage_reached")
    print("Sessions by max stage:", cur.fetchall())
    con.close()

if __name__ == "__main__":
    main()
