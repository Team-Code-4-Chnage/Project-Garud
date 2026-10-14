"""
Unit tests for the deterministic Heartbleed (CVE-2014-0160) signature detector.
These construct raw TLS record bytes directly rather than relying on a real
pcap sample, since the exploit's signature is a wire-format invariant that
doesn't depend on any specific capture.
"""
from app.signatures import detect_heartbleed


def _tls_record(content_type: int, fragment: bytes) -> bytes:
    """Build a single TLS record: type(1) + version(2) + length(2) + fragment."""
    length = len(fragment)
    return bytes([content_type, 0x03, 0x01, (length >> 8) & 0xFF, length & 0xFF]) + fragment


def test_malicious_heartbleed_request_detected():
    heartbeat_fragment = bytes([0x01, 0x40, 0x00])
    record = _tls_record(24, heartbeat_fragment)
    assert detect_heartbleed(record) is True


def test_legitimate_heartbeat_not_flagged():
    real_payload = b"abc"
    padding = b"\x00" * 16
    heartbeat_fragment = bytes([0x01, 0x00, len(real_payload)]) + real_payload + padding
    record = _tls_record(24, heartbeat_fragment)
    assert detect_heartbleed(record) is False


def test_non_heartbeat_tls_traffic_not_flagged():
    record = _tls_record(23, b"\x01\xff\xff" + b"x" * 50)
    assert detect_heartbleed(record) is False


def test_empty_payload_not_flagged():
    assert detect_heartbleed(b"") is False


def test_non_tls_traffic_not_flagged():
    assert detect_heartbleed(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") is False


def test_multiple_records_finds_malicious_one_after_benign():
    real_payload = b"ok"
    benign_fragment = bytes([0x01, 0x00, len(real_payload)]) + real_payload + b"\x00" * 16
    benign_record = _tls_record(24, benign_fragment)

    malicious_fragment = bytes([0x01, 0x40, 0x00])
    malicious_record = _tls_record(24, malicious_fragment)

    assert detect_heartbleed(benign_record + malicious_record) is True
