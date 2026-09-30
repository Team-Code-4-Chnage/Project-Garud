"""
File upload and offline analysis: any layout is converted to the model features, time is taken from the
file, labels are read or predicted, and none of it reaches the live system.
"""
import gzip
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import FLOW_FEATURES
from app.flow_schema import SchemaError, adapt_frame, norm
from app.labels import behaviour_of
from app.main import app
from app.model_loader import artifacts

FIX = Path(__file__).parent / "fixtures"
SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"
TAB = chr(9)
NL = chr(10)


@pytest.fixture(scope="module")
def client():
    if not artifacts.is_loaded:
        artifacts.load()
    with TestClient(app) as tc:
        yield tc


def cic_frame(n=12):
    """Columns and value conventions of the raw CICFlowMeter export."""
    t0 = pd.Timestamp("2017-07-07 03:00:00")
    rows = []
    for i in range(n):
        rows.append({
            " Source IP": "172.16.0.1" if i % 2 else "192.168.10.5", " Destination IP": "192.168.10.50",
            " Source Port": 40000 + i, " Destination Port": 80, " Protocol": 6,
            " Timestamp": (t0 + pd.Timedelta(seconds=15 * i)).strftime("%d/%m/%Y %H:%M:%S"),
            " Flow Duration": 1000 + 10 * i, " Total Fwd Packets": 4, " Total Backward Packets": 2,
            "Total Length of Fwd Packets": 400, " Total Length of Bwd Packets": 900,
            " Fwd Packet Length Mean": 100, " Bwd Packet Length Mean": 450,
            "Flow Bytes/s": "Infinity" if i == 0 else 1300000, " Flow Packets/s": 6000,
            " Flow IAT Mean": 200, " Flow IAT Std": 20, " Fwd IAT Mean": 250, " Bwd IAT Mean": 300,
            " SYN Flag Count": 0, " ACK Flag Count": 1, " FIN Flag Count": 0, " RST Flag Count": 0,
            " PSH Flag Count": 1, " URG Flag Count": 0, " Down/Up Ratio": 0, " Average Packet Size": 216,
            " Fwd Header Length": 100, " Bwd Header Length": 60, "Init_Win_bytes_forward": 8192,
            " Label": "DoS Hulk" if i % 2 else "BENIGN",
        })
    return pd.DataFrame(rows)


def zeek_frame(n=10):
    return pd.DataFrame({
        "ts": [1499400000 + i for i in range(n)], "id.orig_h": ["10.1.1.5"] * n,
        "id.orig_p": [50000 + i for i in range(n)], "id.resp_h": ["10.1.1.9"] * n, "id.resp_p": [443] * n,
        "proto": ["tcp"] * n, "duration": [0.5] * n, "orig_bytes": [300] * n, "resp_bytes": [1200] * n,
        "orig_pkts": [5] * n, "resp_pkts": [4] * n, "history": ["ShADadfF"] * n,
    })


def timeline_frame(minutes=40, per_minute=30, day="2018-03-05", attack=range(20, 28)):
    """Flows on a real timeline: quiet web traffic with a burst of short scan-like flows."""
    rng = np.random.RandomState(0)
    t0 = pd.Timestamp(day + " 10:00:00")
    rows = []
    for m in range(minutes):
        atk = m in attack
        for _ in range(per_minute * (4 if atk else 1)):
            rows.append({
                "Timestamp": (t0 + pd.Timedelta(minutes=m, seconds=float(rng.uniform(0, 59)))).isoformat(),
                "Src IP": "10.0.0.99" if atk else f"10.0.0.{rng.randint(2, 20)}",
                "Dst IP": "10.0.1.5", "Dst Port": int(rng.randint(1, 60000)) if atk else 443, "Protocol": 6,
                "Flow Duration": int(rng.randint(2, 30)) if atk else int(rng.randint(50_000, 3_000_000)),
                "Tot Fwd Pkts": 1 if atk else int(rng.randint(3, 20)),
                "Tot Bwd Pkts": 0 if atk else int(rng.randint(2, 20)),
                "TotLen Fwd Pkts": 0 if atk else int(rng.randint(200, 4000)),
                "TotLen Bwd Pkts": 0 if atk else int(rng.randint(500, 9000)),
                "SYN Flag Cnt": 1 if atk else 0, "ACK Flag Cnt": 0 if atk else 1,
                "Label": "PortScan" if atk else "Benign",
            })
    return pd.DataFrame(rows)


# --- conversion ------------------------------------------------------------------------------------------

def test_norm_makes_names_comparable():
    assert norm(" Flow Bytes/s") == norm("flow_bytes_s") == "flow_bytes_s"


def test_cic_columns_are_mapped_like_the_training_pipeline():
    feats, meta, rep = adapt_frame(cic_frame().astype(str))
    assert rep["format"] == "cicflowmeter" and list(feats.columns) == FLOW_FEATURES
    assert feats["flow_bytes_s"].iloc[0] == 0.0 and feats["ttl_variance"].iloc[0] == 40.0
    assert feats["tcp_win_size"].iloc[0] == 8192 and rep["nonfinite_values_set_to_zero"] == 1
    assert meta["timestamp"].iloc[0] == pd.Timestamp("2017-07-07 03:00:00", tz="UTC")


def test_zeek_columns_are_derived_and_reported():
    feats, meta, rep = adapt_frame(zeek_frame().astype(str))
    assert rep["format"] == "zeek_conn" and feats["flow_duration"].iloc[0] == 500000.0
    assert feats["tot_fwd_pkts"].iloc[0] == 5 and feats["fwd_pkt_len_mean"].iloc[0] == 60
    assert feats["syn_flag_cnt"].iloc[0] == 2 and "psh_flag_cnt" in rep["defaulted"]
    assert meta["protocol"].iloc[0] == "TCP" and meta["timestamp"].iloc[0].year == 2017


def test_unrecognised_table_is_rejected_with_the_columns_it_saw():
    with pytest.raises(SchemaError) as exc:
        adapt_frame(pd.DataFrame({"name": ["a"], "colour": ["b"]}))
    assert "name" in str(exc.value)


@pytest.mark.parametrize("stamp,expected", [
    ("2018-02-23T08:18:29Z", "2018-02-23 08:18:29"),
    ("23/02/2018 08:18:29", "2018-02-23 08:18:29"),        # day above 12: day-first
    ("02/23/2018 08:18:29", "2018-02-23 08:18:29"),        # second number above 12: month-first
    ("2018-02-23 10:18:29+02:00", "2018-02-23 08:18:29"),  # offsets become UTC
    ("1519373909", "2018-02-23 08:18:29"),                 # epoch seconds
    ("1519373909000", "2018-02-23 08:18:29"),              # epoch milliseconds
])
def test_timestamps_of_every_style_land_on_the_right_date(stamp, expected):
    df = zeek_frame(3).drop(columns=["ts"])
    df["Timestamp"] = [stamp] * 3
    _, meta, _ = adapt_frame(df.astype(str))
    assert meta["timestamp"].iloc[0] == pd.Timestamp(expected, tz="UTC")


def test_date_and_time_in_separate_columns_are_combined():
    df = zeek_frame(3).drop(columns=["ts"])
    df["date"], df["time"] = ["2019-06-01"] * 3, ["10:00:05", "10:01:10", "10:02:15"]
    _, meta, _ = adapt_frame(df.astype(str))
    assert meta["timestamp"].iloc[1] == pd.Timestamp("2019-06-01 10:01:10", tz="UTC")


def test_duration_in_seconds_is_detected_from_the_rates_and_corrected():
    df = cic_frame(40)
    df[" Flow Duration"] = 0.5                        # seconds, although the column has the CIC name
    df[" Total Fwd Packets"], df[" Total Backward Packets"] = 3, 3
    df[" Flow Packets/s"] = 12                         # 6 packets in 0.5 s
    feats, _, rep = adapt_frame(df.astype(str))
    assert feats["flow_duration"].iloc[1] == pytest.approx(500_000)
    assert any("converted to microseconds" in a for a in rep["assumptions"])


@pytest.mark.parametrize("label,expected", [
    ("DoS Hulk", "DoS"), ("FTP-Patator", "BruteForce"), ("Brute Force -Web", "WebAttack"),
    ("Infilteration", "Infiltration"), ("DDoS attacks-LOIC-HTTP", "DDoS"), ("BENIGN", "Benign"), ("0", "Benign"),
    ("Reconnaissance", "PortScan"), ("mystery", "Unknown"),
])
def test_labels_map_to_behaviours(label, expected):
    assert behaviour_of(label) == expected


# --- reading containers and layouts -----------------------------------------------------------------------

def upload(client, name, data, path="/offline/analyze"):
    return client.post(path, files={"file": (name, io.BytesIO(data), "application/octet-stream")})


def live_state(client):
    return (
        client.get("/dashboard/stats").json(), client.get("/network/sources").json(),
        client.get("/alerts/stats").json(),
        sorted(n["id"] for n in client.get("/graph/topology_geo").json()["nodes"]),
        len(client.get("/flows/recent").json()),
    )


def csv_bytes(df, **kw):
    return df.to_csv(index=False, **kw).encode()


ZEEK_NATIVE = (
    "#separator \\x09" + NL + "#set_separator" + TAB + "," + NL + "#empty_field" + TAB + "(empty)" + NL
    + "#unset_field" + TAB + "-" + NL + "#path" + TAB + "conn" + NL
    + "#fields" + TAB + TAB.join(["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration",
                                  "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "history"]) + NL
    + "#types" + TAB + TAB.join(["time"] + ["string"] * 11) + NL
    + NL.join(TAB.join([str(1499400000 + 20 * i), "10.1.1.5", str(40000 + i), "10.1.1.9", "80", "tcp", "0.4",
                        "200", "900", "4", "3", "ShADadFf"]) for i in range(60)) + NL + "#close" + TAB + "2017-07-07" + NL
)


@pytest.mark.parametrize("name,payload", [
    ("comma.csv", lambda: csv_bytes(cic_frame(60))),
    ("tab.tsv", lambda: csv_bytes(cic_frame(60), sep=TAB)),
    ("semicolon.csv", lambda: csv_bytes(cic_frame(60), sep=";")),
    ("pipe.txt", lambda: csv_bytes(cic_frame(60), sep="|")),
    ("bom.csv", lambda: b"\xef\xbb\xbf" + csv_bytes(cic_frame(60))),
    ("utf16.csv", lambda: csv_bytes(cic_frame(60)).decode().encode("utf-16")),
    ("comments.csv", lambda: b"# exported by tool" + NL.encode() + csv_bytes(cic_frame(60))),
    ("flows.csv.gz", lambda: gzip.compress(csv_bytes(cic_frame(60)))),
    ("flows.json", lambda: json.dumps(json.loads(cic_frame(60).to_json(orient="records"))).encode()),
    ("flows.ndjson", lambda: cic_frame(60).to_json(orient="records", lines=True).encode()),
    ("conn.log", lambda: ZEEK_NATIVE.encode()),
])
def test_every_container_and_layout_is_read(client, name, payload):
    res = upload(client, name, payload())
    assert res.status_code == 200, res.text
    assert res.json()["rows"] == 60


def test_zip_and_parquet_are_read(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("inside/flows.csv", csv_bytes(cic_frame(60)))
    assert upload(client, "a.zip", buf.getvalue()).json()["rows"] == 60
    pq = io.BytesIO()
    cic_frame(60).astype(str).to_parquet(pq)
    assert upload(client, "a.parquet", pq.getvalue()).json()["rows"] == 60


def test_suricata_style_nested_json_is_read(client):
    recs = [{"timestamp": f"2019-01-01T10:{i // 6:02d}:{(i % 6) * 10:02d}.000000+0000", "src_ip": "10.0.0.1",
             "dest_ip": "10.0.0.2", "dest_port": 22, "proto": "TCP",
             "flow": {"pkts_toserver": 5, "pkts_toclient": 4, "bytes_toserver": 500, "bytes_toclient": 900, "age": 3}}
            for i in range(60)]
    body = upload(client, "eve.json", json.dumps(recs).encode()).json()
    assert body["rows"] == 60 and body["schema"]["format"] == "suricata_eve"
    assert "flow_duration" in body["schema"]["derived"]


def test_headerless_file_with_the_22_features_is_accepted(client):
    too_narrow = csv_bytes(cic_frame(60)[list(cic_frame().columns)[:5]], header=False)
    assert upload(client, "x.csv", too_narrow).status_code == 422
    feats, _, _ = adapt_frame(cic_frame(60).astype(str))
    res = upload(client, "raw.csv", csv_bytes(feats, header=False))
    assert res.status_code == 200 and res.json()["rows"] == 60


def test_offline_rejects_unusable_files(client):
    assert upload(client, "empty.csv", b"").status_code == 422
    assert upload(client, "junk.csv", b"a,b" + NL.encode() + b"1,2" + NL.encode()).status_code == 422
    workbook = io.BytesIO()
    with zipfile.ZipFile(workbook, "w") as z:
        z.writestr("xl/workbook.xml", "<x/>")
    res = upload(client, "book.xlsx", workbook.getvalue())
    assert res.status_code == 422 and "Excel" in res.text


def test_no_size_limit(client):
    df = cic_frame(6)
    df["note"] = "x" * 2_000_000
    big = csv_bytes(df)
    assert len(big) > 10 * 1024 * 1024
    assert upload(client, "big.csv", big).json()["rows"] == 6


# --- analysis on the file's own timeline ---------------------------------------------------------------------

def test_forecast_uses_the_dates_in_the_file(client):
    body = upload(client, "t.csv", csv_bytes(timeline_frame())).json()
    seg = body["segments"][0]
    assert seg["start"].startswith("2018-03-05T10:00") and seg["end"].startswith("2018-03-05T10:39")
    assert body["timeline"]["synthesized"] is False
    assert seg["forecast"]["steps"][0]["minute"].startswith("2018-03-05T10:40")
    assert len(seg["forecast"]["steps"]) == 4 and len(seg["per_minute"]) == 40


def test_a_gap_in_the_data_splits_the_timeline_into_periods(client):
    df = pd.concat([timeline_frame(day="2018-03-05"), timeline_frame(day="2018-03-07")])
    body = upload(client, "two_days.csv", csv_bytes(df)).json()
    days = sorted(s["start"][:10] for s in body["segments"] if s["status"] == "ok")
    assert days == ["2018-03-05", "2018-03-07"] and body["timeline"]["segments_total"] == 2


def test_labelled_file_is_scored_against_its_labels_and_backtested(client):
    body = upload(client, "t.csv", csv_bytes(timeline_frame())).json()
    ev = body["evaluation"]
    assert body["labels"]["source"] == "file" and ev["malicious"] > 0
    bt = body["segments"][0]["backtest"]
    assert bt["attack_minutes"] == 8 and len(bt["per_horizon"]) == 4
    assert "state_evaluation" in body["segments"][0]


def test_unlabelled_file_gets_predicted_labels_and_claims_no_accuracy(client):
    df = timeline_frame().drop(columns=["Label"])
    body = upload(client, "u.csv", csv_bytes(df)).json()
    assert body["labels"]["source"] == "predicted" and body["evaluation"] is None
    assert "backtest" not in body["segments"][0]
    assert any("no ground truth" in n for n in body["notes"])
    assert "Benign" in body["labels"]["predicted_counts"]
    conv = upload(client, "u.csv", csv_bytes(df), path="/offline/convert")
    assert conv.status_code == 200
    out = pd.read_csv(io.StringIO(conv.text))
    assert {"predicted_behaviour", "attack_probability", "confidence"} <= set(out.columns)
    assert list(out.columns[:6]) == ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    assert out["timestamp"].iloc[0].startswith("2018-03-05T10:00")


def test_file_without_addresses_or_timestamps_is_completed_and_says_so(client):
    df = timeline_frame().drop(columns=["Src IP", "Dst IP", "Timestamp"])
    body = upload(client, "bare.csv", csv_bytes(df)).json()
    assert body["timeline"]["synthesized"] is True and body["timeline"]["rows_per_minute"] >= 20
    assert body["sessions_grouping"].startswith("blocks of 30")
    assert any("synthetic" in a for a in body["schema"]["assumptions"])


def test_offline_analysis_never_touches_the_live_system(client):
    before = live_state(client)
    for name, data in (("cic.csv", csv_bytes(cic_frame(60))), ("conn.log", ZEEK_NATIVE.encode()),
                       ("capture.bin", (FIX / "cic2017_parity.pcap").read_bytes())):
        assert upload(client, name, data).status_code == 200
    assert live_state(client) == before


def test_pcap_is_detected_by_content(client):
    pytest.importorskip("scapy")
    body = upload(client, "capture.bin", (FIX / "cic2017_parity.pcap").read_bytes()).json()
    assert body["input_kind"] == "pcap" and body["rows"] == 24


# --- the bundled real-data samples ----------------------------------------------------------------------------

def test_heldout_2017_sample_is_detected_accurately(client):
    body = upload(client, "s.csv.gz", (SAMPLES / "cic2017_tuesday_ssh_patator_heldout.csv.gz").read_bytes()).json()
    ev, seg = body["evaluation"], body["segments"][0]
    assert body["rows"] == 49576 and seg["start"].startswith("2017-07-04T17:59") and seg["minutes"] == 61
    assert ev["roc_auc"] > 0.98 and ev["recall"] > 0.9 and ev["false_positive_rate"] < 0.01
    assert seg["backtest"]["attack_minutes"] > 0 and len(seg["forecast"]["steps"]) == 4


def test_2018_sample_without_addresses_runs_and_reports_its_difficulty(client):
    body = upload(client, "s.csv", (SAMPLES / "cic2018_infiltration_sample.csv").read_bytes()).json()
    assert body["rows"] == 5828 and body["sessions_grouping"].startswith("blocks of 30")
    assert body["segments"][0]["status"] == "ok"


def test_legacy_ingest_csv_still_feeds_the_live_system_without_a_size_limit(client):
    df = cic_frame(6)
    df["note"] = "x" * 2_000_000
    res = upload(client, "big.csv", csv_bytes(df), path="/ingest/csv")
    assert res.status_code == 200 and res.json()["flows_accepted"] == 6
