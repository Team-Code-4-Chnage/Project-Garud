"""Download a time window out of a huge remote pcapng using HTTP Range requests.

Usage: python pcap_slice.py <day> <start HH:MM> <end HH:MM> <out.pcapng> [max_mb]
Times are local capture time (ADT, UTC-3) as published in the CIC-IDS2017 schedule.
"""
import struct
import sys
import datetime as dt
import urllib.request

BASE = "https://huggingface.co/datasets/Ariasyah/cic-ids-2017/resolve/main/pcap/"
FILES = {
    "mon": ("Monday-WorkingHours.pcap", dt.date(2017, 7, 3)),
    "tue": ("Tuesday-WorkingHours.pcap", dt.date(2017, 7, 4)),
    "wed": ("Wednesday-workingHours.pcap", dt.date(2017, 7, 5)),
    "thu": ("Thursday-WorkingHours.pcap", dt.date(2017, 7, 6)),
    "fri": ("Friday-WorkingHours.pcap", dt.date(2017, 7, 7)),
}
ADT = dt.timezone(dt.timedelta(hours=-3))
EPB = 6


def _get_once(url, start, end):
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def get(url, start, end, step=4_000_000):
    out = bytearray()
    pos = start
    while pos <= end:
        e = min(pos + step - 1, end)
        for attempt in range(6):
            try:
                b = _get_once(url, pos, e)
                break
            except Exception as ex:
                print("retry", pos, ex, flush=True)
        else:
            raise SystemExit("download failed")
        out += b
        pos += len(b)
    return bytes(out)


def size_of(url):
    req = urllib.request.Request(url, headers={"Range": "bytes=0-0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers["Content-Range"].split("/")[1])


class PcapNG:
    def __init__(self, url):
        self.url = url
        self.size = size_of(url)
        head = get(url, 0, 65535)
        if head[:4] != b"\x0a\x0d\x0d\x0a":
            raise SystemExit("not pcapng")
        bom = head[8:12]
        self.e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        self.tsdiv = 1_000_000
        i = 0
        while True:
            btype, blen = struct.unpack(self.e + "II", head[i:i + 8])
            if btype == EPB:
                break
            if btype == 1:
                self._parse_idb(head[i:i + blen])
            i += blen
        self.header = head[:i]

    def _parse_idb(self, blk):
        j = 16
        while j + 4 <= len(blk) - 4:
            code, ln = struct.unpack(self.e + "HH", blk[j:j + 4])
            if code == 0:
                break
            if code == 9:
                v = blk[j + 4]
                self.tsdiv = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
            j += 4 + ((ln + 3) // 4) * 4

    def _epb_at(self, buf, i, lo, hi):
        if i + 32 > len(buf):
            return None
        btype, blen, iface, th, tl, cap, orig = struct.unpack(self.e + "IIIIIII", buf[i:i + 28])
        if btype != EPB or blen % 4 or not (32 <= blen <= 300000) or iface > 16:
            return None
        if cap > orig or cap + 32 > blen or i + blen > len(buf):
            return None
        if struct.unpack(self.e + "I", buf[i + blen - 4:i + blen])[0] != blen:
            return None
        ts = ((th << 32) | tl) / self.tsdiv
        if not (lo <= ts <= hi):
            return None
        return blen, ts

    def resync(self, buf, lo, hi):
        for i in range(0, len(buf) - 32):
            j, ok = i, True
            for _ in range(3):
                r = self._epb_at(buf, j, lo, hi)
                if r is None:
                    ok = False
                    break
                j += r[0]
            if ok:
                return i, self._epb_at(buf, i, lo, hi)[1]
        return None, None

    def ts_at(self, off, lo, hi):
        buf = get(self.url, off, min(off + 600_000, self.size - 1))
        i, ts = self.resync(buf, lo, hi)
        return (None, None) if i is None else (ts, off + i)

    def find_offset(self, target, lo_ts, hi_ts):
        lo, hi = len(self.header), self.size - 700_000
        while hi - lo > 1_500_000:
            mid = (lo + hi) // 2
            ts, _ = self.ts_at(mid, lo_ts, hi_ts)
            if ts is None or ts < target:
                lo = mid
            else:
                hi = mid
        _, exact = self.ts_at(lo, lo_ts, hi_ts)
        return exact


def main():
    day, t0, t1, out = sys.argv[1:5]
    max_mb = float(sys.argv[5]) if len(sys.argv) > 5 else 400
    fname, date = FILES[day]
    p = PcapNG(BASE + fname)
    day_lo = dt.datetime.combine(date, dt.time(0, 0), ADT).timestamp()
    day_hi = day_lo + 86400
    h0, m0 = map(int, t0.split(":"))
    h1, m1 = map(int, t1.split(":"))
    ts0 = dt.datetime.combine(date, dt.time(h0, m0), ADT).timestamp()
    ts1 = dt.datetime.combine(date, dt.time(h1, m1), ADT).timestamp()
    start = p.find_offset(ts0, day_lo, day_hi)
    end = p.find_offset(ts1, day_lo, day_hi)
    end = min(end, start + int(max_mb * 1e6))
    print(f"{fname}: bytes {start}-{end} ({(end - start) / 1e6:.1f} MB)", flush=True)
    data = get(p.url, start, end)
    n, i, first = 0, 0, None
    with open(out, "wb") as f:
        f.write(p.header)
        while i + 12 <= len(data):
            btype, blen = struct.unpack(p.e + "II", data[i:i + 8])
            if blen < 12 or i + blen > len(data):
                break
            if btype == EPB:
                if first is None:
                    th, tl = struct.unpack(p.e + "II", data[i + 12:i + 20])
                    first = ((th << 32) | tl) / p.tsdiv
                n += 1
            f.write(data[i:i + blen])
            i += blen
    print(f"wrote {n} packets to {out}; first packet at "
          f"{dt.datetime.fromtimestamp(first, ADT):%H:%M:%S} ADT", flush=True)


if __name__ == "__main__":
    main()
