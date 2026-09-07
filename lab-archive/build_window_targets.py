#!/usr/bin/env python3
"""Extract per-(host,5min-window) outbound destination sets from a real
conn.log, aligned to feature_engine.py window_start formatting, so the UEBA
rule can judge new/rare against the baseline known-target dictionary instead
of relying on first-seen within a short log (the "cold-start new_dst" trap).

Usage: python3 build_window_targets.py <zeek_log_dir> [seconds=300] > window_targets.json
Output: {"host": {"YYYY-mm-dd HH:MM:SS": {"dsts": [...], "counts": {dst: n}}}}
"""
import json, os, sys, time
from collections import defaultdict

def parse_zeek_log(path):
    import gzip
    opener = gzip.open if path.endswith(".gz") else open
    fields = None
    with opener(path, "rt", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.strip().split("\t")[1:]
            elif line.startswith("#") or not line.strip():
                continue
            elif fields:
                yield dict(zip(fields, line.rstrip("\n").split("\t")))

def to_f(x):
    try:
        return float(x)
    except:
        return 0.0

def main():
    logdir = sys.argv[1]
    window = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    out = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {"n": 0, "ob": 0})))
    for fn in os.listdir(logdir):
        if not fn.startswith("conn.log"):
            continue
        for r in parse_zeek_log(os.path.join(logdir, fn)):
            oh, rh = r.get("id.orig_h", ""), r.get("id.resp_h", "")
            if not (oh.startswith("172.20.") or oh.startswith("10.6.")):
                continue
            ts = to_f(r.get("ts"))
            widx = int(ts // window)
            wstart = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(widx * window))
            out[oh][wstart][rh]["n"] += 1
            out[oh][wstart][rh]["ob"] += to_f(r.get("orig_bytes", 0))
    final = {h: {w: {"dsts": sorted(c.keys()),
                     "counts": {d: c[d]["n"] for d in c},
                     "ob_bytes": {d: c[d]["ob"] for d in c}}
                 for w, c in ws.items()} for h, ws in out.items()}
    json.dump(final, sys.stdout, indent=1, sort_keys=True)

if __name__ == "__main__":
    main()