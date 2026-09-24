# PCAP and Live Feature Parity with the Training Data

The model was trained on CICFlowMeter output (the CIC-IDS2017/2018 flow files). For its predictions on uploaded PCAPs or live traffic to mean anything, the extractor that turns packets into flows must produce the same 22 numbers CICFlowMeter would. This document records how that was measured, what CICFlowMeter actually does (including its bugs), and the result.

## Method

`experiments/pcap_parity.py` takes a slice of an original CIC-IDS2017 capture and the official labelled flow file for the same day (which carries Flow ID, IPs, ports, protocol, a minute timestamp and all CICFlowMeter columns). It rebuilds flows from the packets, matches each one to the official flow with the same 5-tuple and start minute, converts the official columns into model features exactly as `data/preprocess_cicids.py` does, and reports per-feature agreement (within 1% relative, or 1e-6 absolute).

Flows that cross the capture boundary are skipped and counted, not scored:
- the labelled flow runs past the end of the slice;
- the 5-tuple already had a labelled flow open when the slice began, so CICFlowMeter would have appended the packets to it;
- a TCP flow that does not both open (SYN without ACK) and close (FIN or RST) inside the slice;
- a non-TCP flow within 2 s of either edge.

Captures are about 25 MB slices of the original day-long files (Hugging Face mirror `Ariasyah/cic-ids-2017`, folder `pcap/`); label files are from the same mirror (`traffic_labels/`, fetched by `data/fetch_cic2017_labelled.py`).

## Result

Mean agreement over the 22 model features on the same compared flows, before (extractor at commit 6409c0b) and after.

| Capture (UTC) | Flows compared | Before | After | Attack flows compared | Attack flows before / after |
|---|---|---|---|---|---|
| Tue 2017-07-04 12:18:56, 16 s, benign | 209 | 45.3% | 99.8% | none in slice | |
| Tue 12:24:59, 3 s, during FTP-Patator | 17 | 13.4% | 95.2% | 0 (attack connections outlast the 3 s slice) | |
| Wed 2017-07-05 12:49:57, 117 s, DoS | 905 | 52.4% | 99.8% | 22 DoS slowloris | 37.2% / 92.1% |
| Thu 2017-07-06 12:24:17, 143 s, web attack | 1,484 | 56.3% | 99.3% | 78 Web Attack Brute Force | 15.1% / 100.0% |
| Fri 2017-07-07 19:04:58, 23 s, DDoS | 1,307 | 30.7% | 99.6% | 990 DDoS | 13.0% / 99.9% |
| Fri 17:09:53, 124 s, benign | 1,463 | 54.6% | 99.2% | none in slice | |

Tuesday is scored with `--no-padding` (see the padding rule below). Direction agreement is 99.3% to 100% after the change (44% to 96% before), and packet counts match exactly in 98% to 99.6% of flows.

Model-level check (`experiments/pcap_model_parity.py`): the shipped model scored the same 6-flow windows twice, once with PCAP-extracted features and once with the official features. Alert decisions agreed on 99.1% to 100% of windows and predicted stages on 100%. Every attack window (slowloris, web brute force, DDoS) alerted on both paths; benign windows alerted on at most 0.9% (PCAP) versus 0% (official). These attack families are in the training data, so this shows the pipeline is faithful, not that the model generalises.

Regression tests: `backend/tests/test_pcap_parity_real.py` holds 24 real flows (12 web brute force, 12 benign) cut from the Thursday capture with their official label rows. It checks all 22 features and uploads the file through the real `/ingest/pcap` route. `backend/tests/test_cic_semantics.py` checks each rule below on constructed packets.

## What CICFlowMeter does (as measured)

These are the rules the extractor (`capture/flow_table.py`, `capture/flow_state.py`) now follows. Several are bugs in CICFlowMeter; they are reproduced because the model learned from their output.

| Aspect | CICFlowMeter behaviour | Evidence |
|---|---|---|
| Direction | Forward = direction of the flow's first packet | Direction agreement 44% to 100% after the change |
| Flow end | Closed by the first FIN or RST (the teardown then starts a second flow) or 120 s after the flow's first packet | Packet counts exact in 98% to 99.6% |
| Minimum size | Single-packet flows are never written | 0 of 445,909 Tuesday flows have one packet |
| Packet length | Transport payload bytes, not IP length | Payload means match exactly |
| Ethernet padding | Counted as payload on Wednesday, Thursday and Friday (every clean case: 12, 28, 426); not counted on Tuesday (38 of 38). Default is to count it | Per-day check in the parity run |
| Timestamps | Whole microseconds | IAT values in the files are integers |
| Duration | No floor; flows whose packets share a timestamp have rate = infinity, which training replaced with 0 | Rates match |
| IAT std | Sample standard deviation (n - 1) | Matches to 1e-9 relative |
| Average Packet Size | First packet's payload counted twice: (sum + first) / n | e.g. two 48-byte packets give 72 |
| Down/Up Ratio | Integer division backward / forward | Matches 99.5% |
| Header Length | Sum of TCP header bytes per direction. For non-TCP packets, the header length of the last TCP packet the tool parsed (stale state) | 196 of 196 UDP flows |
| Init_Win_bytes_forward | TCP window of the first forward packet; -1 when the flow is not TCP | 100% |
| Flag Count columns | 0/1 values from the flow's first packet only, with SYN and PSH swapped: PSH column = first packet SYN bit (100%), ACK column = first packet ACK bit (100%), SYN column = first packet PSH bit (97%) | Bit-by-bit search over 233 flows |
| URG Flag Count | No packet-bit rule found; emitting 0 agrees 90% of the time | Open |
| FIN / RST Flag Count | Assumed first packet's own bit; no non-zero case seen in the slices | Open |

Consequences for the feature names used by the model:
- `ttl_variance` is |forward header bytes - backward header bytes|. The CIC files contain no TTL; the name is historical.
- `retransmit_cnt` is 0 in every training row and carries no information.
- The six flag features describe the first packet of the flow, not flag counts.

Real TTL statistics, retransmission counts and payload-size spread are computed separately by `FlowState.packet_features()`. They are not model inputs, because no training data contains them in CICFlowMeter's form.

## Not covered

- FTP/SSH-Patator attack flows: they last several seconds, and at about 7.5 MB/s on the Tuesday link a complete flow needs a slice of a few hundred MB, which was not downloaded.
- Port-scan attack flows: the Friday slice at 17:10 UTC contained no scan flows (the scan runs in bursts).
- Heartbleed, infiltration, bot: not sliced.
- CIC-IDS2018: not checked; its files were produced by a newer CICFlowMeter release and may differ.
- Live capture on a real network interface: same code path as PCAP upload (`test_flow_parity.py` checks both give identical features), but not run against labelled traffic.

## Reproduce

```
python data/fetch_cic2017_labelled.py --out data/cic2017_labelled
# slice a capture window by local time (UTC-3), about 25 MB, via HTTP range requests:
python experiments/pcap_slice.py thu 09:25 09:27 thu_web.pcapng 25
python experiments/pcap_parity.py --pcap thu_web.pcapng --labels data/cic2017_labelled/Thursday-WorkingHours-Morning-WebAttacks.parquet
python experiments/pcap_parity.py --pcap thu_web.pcapng --labels ... --dump matched_thu_web.csv
python experiments/pcap_model_parity.py matched_thu_web.csv
python -m pytest backend/tests/test_pcap_parity_real.py backend/tests/test_cic_semantics.py
```
