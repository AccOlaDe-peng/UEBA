#!/usr/bin/env python3
"""Build UEBA baseline snapshot from a feature CSV + known-targets JSON.

Reads the per-(host,5min) feature vectors (feature_engine.py output) and
aggregates per (host, hour-of-day) percentiles for the rule-scoring features,
plus the per-host known-target dictionary (from targets.json / synthetic
history). Sprint 3 consumes this snapshot to evaluate new_dst / P99 rules and
to warm an Isolation Forest without waiting for 24h+ of real observation.

Usage: python3 build_baseline.py <features.csv> <targets.json> <out.json>
Prints the 24h profile + day/night percentile table for the active host(s).
"""
import json, sys
from collections import defaultdict

FEATS = ["outbound_bytes", "upload_download_ratio", "connection_count",
         "unique_dst_ip", "avg_duration"]

def pct(xs, p):
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (len(s) - 1) * p / 100.0
    lo = int(k); hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)

def main():
    feat_csv, target_json, out_json = sys.argv[1], sys.argv[2], sys.argv[3]
    targets = json.load(open(target_json))

    by_host = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for line in open(feat_csv):
        if line.startswith("host,") or not line.strip():
            continue
        cols = line.rstrip("\n").split(",")
        host = cols[0]
        rec = dict(zip(
            ["host","window_start","outbound_bytes","inbound_bytes",
             "upload_download_ratio","connection_count","unique_dst_ip",
             "unique_dst_port","new_dst_ip_count","rare_dst_ip_count",
             "avg_duration","max_duration","failed_connection_ratio",
             "dns_query_count","unique_domain_count","night_activity_ratio"], cols))
        hour = int(rec["window_start"][11:13])
        for f in FEATS:
            try:
                by_host[host][hour][f].append(float(rec[f]))
            except (KeyError, ValueError):
                pass

    out = {}
    for host, hours in by_host.items():
        hh = {}
        for hour, feats in sorted(hours.items()):
            hh[str(hour)] = {f: {"p50": round(pct(feats[f], 50), 3),
                                 "p95": round(pct(feats[f], 95), 3),
                                 "p99": round(pct(feats[f], 99), 3)}
                             for f in FEATS}
        # active hours = any hour whose windows actually had outbound conns
        active = [h for h in sorted(hours) if max(hours[h]["connection_count"]) > 0]
        out[host] = {"hourly": hh, "active_hours": active,
                     "targets": targets.get(host, {})}
    with open(out_json, "w") as f:
        json.dump({"meta": {
            "source": "synthetic_history.py (seed=42, days=14) -> feature_engine.py",
            "generated": "2026-08-26",
            "purpose": "warm-start UEBA baseline before 24h real data"},
            "hosts": out}, f, indent=2, sort_keys=True)

    # ---- preview ----
    for host, hours in sorted(by_host.items()):
        act = [h for h in hours if max(hours[h]["connection_count"]) > 0]
        print(f"\n=== host {host}  active_hours={act} ===")
        print("小时 | outbound P50(MB) | P95(MB) |P99(MB) | conn counts(med)")
        for h in range(24):
            g = hours.get(h)
            if not g or not any(g["connection_count"]):
                continue
            ob = g["outbound_bytes"]
            print(f"  {h:02d} | {pct(ob,50)/1e6:>12.1f} | {pct(ob,95)/1e6:>8.1f} | {pct(ob,99)/1e6:>7.1f} | {pct(g['connection_count'],50):>11.0f}")
        day   = [v for h, v in hours.items() if 7 <= h <= 21]
        night = [v for h, v in hours.items() if h <= 5]
        def row(label, grp):
            if not grp or not grp[0]["connection_count"]:
                return
            ob = [v for g in grp for v in (g["outbound_bytes"] if g["connection_count"] else [])]
            nd = [g["unique_dst_ip"] for g in grp for _ in ([g] if g["connection_count"] else [])]
            print(f"  {label:<8} outbound P50/P95/P99= {pct(ob,50)/1e6:.1f}/{pct(ob,95)/1e6:.1f}/{pct(ob,99)/1e6:.1f} MB   unique_dst P95= {pct(nd,95):.1f}")
        print(f"  目标字典: {len(targets.get(host,{}))} 个历史目标; 外传目标 EXTERNAL 181 出现次数= {targets.get(host,{}).get('172.20.69.181',0)}")

if __name__ == "__main__":
    main()