#!/usr/bin/env python3
"""Sprint 2 Feature Engine: Zeek logs -> per-host per-window feature vectors.
Usage: python3 feature_engine.py <zeek_log_dir> [--window 300] [--out features.csv]
Entity: (host, time_window). 窗口默认 300s (5min)。
"""
import csv, json, os, sys, time
from collections import defaultdict

def parse_zeek_log(path):
    """Yield dict rows from a Zeek TSV log (supports gzip via zcat fallback)."""
    import gzip, subprocess
    opener = gzip.open if path.endswith(".gz") else open
    fields = None
    with opener(path, "rt", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.strip().split("\t")[1:]
            elif line.startswith("#") or not line.strip():
                continue
            elif fields:
                vals = line.rstrip("\n").split("\t")
                yield dict(zip(fields, vals))

def load_logs(logdir):
    conns, https, dnss = [], [], []
    for fn in os.listdir(logdir):
        p = os.path.join(logdir, fn)
        if fn.startswith("conn.log"):
            for r in parse_zeek_log(p): conns.append(r)
        elif fn.startswith("http.log"):
            for r in parse_zeek_log(p): https.append(r)
        elif fn.startswith("dns.log"):
            for r in parse_zeek_log(p): dnss.append(r)
    return conns, https, dnss

def to_int(x):
    try: return int(float(x))
    except (TypeError, ValueError): return 0

def to_f(x):
    try: return float(x)
    except (TypeError, ValueError): return 0.0

def main():
    logdir = sys.argv[1]
    window = 300
    out = "features.csv"
    args = sys.argv[2:]
    if "--window" in args: window = int(args[args.index("--window")+1])
    if "--out" in args: out = args[args.index("--out")+1]
    conns, https, dnss = load_logs(logdir)
    print(f"loaded: conn={len(conns)} http={len(https)} dns={len(dnss)} window={window}s")

    # conn rows grouped by (host, window)
    groups = defaultdict(list)
    for c in conns:
        try: ts = float(c["ts"])
        except (KeyError, ValueError): continue
        oh = c.get("id.orig_h", ""); rh = c.get("id.resp_h", "")
        for host, peer, direction in ((oh, rh, "out"), (rh, oh, "in")):
            if host.startswith("172.20.") or host.startswith("10.6."):
                groups[(host, int(ts // window))].append((c, peer, direction, ts))

    # global dst popularity (for rare_dst_ip)
    dst_count = defaultdict(int)
    for c in conns:
        dst_count[c.get("id.resp_h", "")] += 1

    # dns per (host, window)
    dns_g = defaultdict(list)
    for d in dnss:
        try: ts = float(d["ts"])
        except (KeyError, ValueError): continue
        dns_g[(d.get("id.orig_h",""), int(ts // window))].append(d)

    FEATURES = ["host","window_start",
        "outbound_bytes","inbound_bytes","upload_download_ratio",
        "connection_count","unique_dst_ip","unique_dst_port",
        "new_dst_ip_count","rare_dst_ip_count","avg_duration","max_duration",
        "failed_connection_ratio","dns_query_count","unique_domain_count",
        "night_activity_ratio"]
    # new_dst_ip: 首次出现于历史（按 ts 排序全局计算首次见到时间）
    first_seen = {}
    for c in sorted(conns, key=lambda x: to_f(x.get("ts"))):
        r = c.get("id.resp_h","")
        if r and r not in first_seen: first_seen[r] = to_f(c.get("ts"))

    rows = []
    for (host, widx), items in sorted(groups.items()):
        wstart = widx * window
        outbound = inbound = conncnt = failed = 0
        dsts, ports = set(), set(); new_dst = rare_dst = 0
        durs = []
        for c, peer, direction, ts in items:
            ob = to_int(c.get("orig_bytes")); rb = to_int(c.get("resp_bytes"))
            if direction == "out":
                outbound += ob; inbound += rb; conncnt += 1
                dsts.add(peer); ports.add(c.get("id.resp_p",""))
                if first_seen.get(peer, 1e18) >= wstart: new_dst += 1
                if dst_count.get(peer,0) <= 2: rare_dst += 1
                durs.append(to_f(c.get("duration")))
                hist = c.get("conn_state","")
                if hist in ("REJ","RSTO","RSTR","S0"): failed += 1
        dns_rows = dns_g.get((host, widx), [])
        domains = {d.get("query","").lower().rstrip(".") for d in dns_rows if d.get("query")}
        lt = time.localtime(wstart)
        night = 1 if (lt.tm_hour < 7 or lt.tm_hour >= 22) else 0
        ratio = (outbound / inbound) if inbound > 0 else (float(outbound > 0))
        rows.append([host, time.strftime("%Y-%m-%d %H:%M:%S", lt),
            outbound, inbound, round(ratio,3), conncnt, len(dsts), len(ports),
            new_dst, rare_dst,
            round(sum(durs)/len(durs),3) if durs else 0.0,
            round(max(durs),3) if durs else 0.0,
            round(failed/conncnt,3) if conncnt else 0.0,
            len(dns_rows), len(domains), night])

    with open(out, "w", newline="") as f:
        wtr = csv.writer(f); wtr.writerow(FEATURES); wtr.writerows(rows)
    print(f"wrote {len(rows)} feature rows -> {out}")

if __name__ == "__main__":
    main()
