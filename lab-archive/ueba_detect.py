#!/usr/bin/env python3
"""Sprint 3 UEBA PoC: cold-started baseline + Isolation Forest + rule evidence
-> explainable Risk Score per (host, 5min-window).

Purely stdlib (targets the minimal Python 3.8 on the lab host).

Usage:
  python3 ueba_detect.py \
      --baseline baseline_synth.json \
      --if-train  features_synth.csv \
      --features  <detection feature csv, feature_engine output> \
      [--hosts 172.20.69.180] [--out report.csv]

Scores:
  rule_score  (0-80)   interpretable rule evidence, baseline from
                       baseline_synth.json (per host, per hour P50/P95/P99 +
                       known-target dict) + new_dst/rare_dst from the window.
  if_pts      (0-20)   IsolationForest anomaly on log-transformed features,
                       trained on the synthetic 14d history.
  risk_score  = rule_score + if_pts  (cap 100)
  level: LOW<40  MED 40-59  HIGH 60-79  CRIT>=80
Rows with no outbound conns are set LOW without scoring (no exfil signal).
"""
import math, random, sys
from collections import defaultdict

random.seed(20260826)

def log10p(x, eps=1e-9):
    return math.log10(max(x, eps) + 1.0)

# feature vector for IF (all numeric, log-compressed so that a 2GB backup is
# NOT automatically the strongest anomaly - rule evidence owns exfil targeting)
IF_FEATS = [
    ("outbound_bytes", lambda v: log10p(v)),
    ("inbound_bytes", lambda v: log10p(v)),
    ("upload_download_ratio", lambda v: log10p(v)),
    ("connection_count", lambda v: log10p(v)),
    ("unique_dst_ip", lambda v: log10p(v)),
    ("unique_dst_port", lambda v: log10p(v)),
    ("avg_duration", lambda v: log10p(v * 100.0)),
    ("max_duration", lambda v: log10p(v * 100.0)),
    ("failed_connection_ratio", lambda v: v * 10.0),
    ("dns_query_count", lambda v: log10p(v)),
    ("unique_domain_count", lambda v: log10p(v)),
]

FEAT_COL = ["host","window_start","outbound_bytes","inbound_bytes",
            "upload_download_ratio","connection_count","unique_dst_ip",
            "unique_dst_port","new_dst_ip_count","rare_dst_ip_count",
            "avg_duration","max_duration","failed_connection_ratio",
            "dns_query_count","unique_domain_count","night_activity_ratio"]

def to_f(v):
    try: return float(v)
    except: return 0.0
def to_i(v):
    return int(to_f(v))

# ---------------- pure-python Isolation Forest ------------------------------
def c_factor(n):
    if n <= 2: return 1.0
    return 2.0 * (math.log(n - 1) + 0.5772156649015329) - 2.0 * (n - 1) / n

def fit_tree(data, depth, max_depth):
    n = len(data)
    if n <= 1 or depth >= max_depth:
        return ("leaf", n)
    mins = [min(r[i] for r in data) for i in range(len(data[0]))]
    maxs = [max(r[i] for r in data) for i in range(len(data[0]))]
    cand = [i for i in range(len(data[0])) if maxs[i] - mins[i] > 1e-9]
    if not cand:
        return ("leaf", n)
    idx = random.choice(cand)
    split = random.uniform(mins[idx], maxs[idx])
    left = [r for r in data if r[idx] < split]
    right = [r for r in data if r[idx] >= split]
    if not left or not right:
        return ("leaf", n)
    return ("node", idx, split, fit_tree(left, depth + 1, max_depth),
            fit_tree(right, depth + 1, max_depth))

def tree_path(node, x, depth):
    if node[0] == "leaf":
        _, n = node
        return depth + c_factor(n), depth + n
    _, idx, split, l, r = node
    if x[idx] < split:
        return tree_path(l, x, depth + 1)
    return tree_path(r, x, depth + 1)

def fit_forest(data, ntrees=40, subsample=64, max_depth=6):
    trees = []
    for _ in range(ntrees):
        sample = random.sample(data, min(subsample, len(data)))
        trees.append(fit_tree(sample, 0, max_depth))
    return trees, c_factor(min(subsample, len(data)))

def forest_score(trees, cmax, x, ntrees):
    total, reach = 0.0, 0
    for t in trees:
        h, depth = tree_path(t, x, 0)
        total += h
        reach += depth
    avg = total / ntrees
    score = 2.0 ** (-avg / cmax)
    return min(1.0, score), max(0, min(1.0, avg / (2 * cmax)))  # score, raw_norm

# ---------------- rules -------------------------------------------------------
def rule_evidence(host, hour, r, base_host, wt):
    tot, pts = 0, []
    ob     = to_f(r["outbound_bytes"])
    ratio  = to_f(r["upload_download_ratio"])
    dur    = to_f(r["avg_duration"])
    hb = (base_host or {}).get("hourly", {}).get(str(hour))

    # new / rare judged against the baseline known-target dictionary, not the
    # first-seen within a short log (avoids the cold-start new_dst trap).
    bi = (base_host or {}).get("targets", {})
    new_heavy = False
    if wt is not None:
        ob_b = wt.get("ob_bytes", {})
        unk = [d for d in wt["dsts"] if d not in bi]
        unk_ob = sum(ob_b.get(d, 0) for d in unk)
        if unk_ob > 100e6:
            new_heavy = True
            tot += 35; pts.append("大量外传至全新目标(>100MB)+35")
        elif unk_ob > 5e6:
            tot += 12; pts.append("外传至全新目标(5-100MB)+12")
        elif unk:
            tot += 5; pts.append("出现新目标但仅小流量+5")
        if sum(ob_b.get(d, 0) for d in wt["dsts"]
               if d in bi and bi[d] <= 3) > 100e6:
            new_heavy = True
            tot += 10; pts.append("向基线低频目标大量外传(>100MB)+10")
    else:
        if to_i(r["new_dst_ip_count"]) > 0:
            tot += 35; pts.append("首次访问目标+35")
        if to_i(r["rare_dst_ip_count"]) > 0:
            tot += 10; pts.append("目标全历史罕见+10")
    if hb:
        # volume/ratio deviations are penalised lightly when all targets are
        # known (routine big backups to the known backup server are NOT high
        # risk); full weight only when a target-level anomaly is already flagged
        if ob > hb["outbound_bytes"]["p99"]:
            p = 20 if new_heavy else 8
            tot += p; pts.append(f"外传量超该小时历史P99+{p}")
        elif ob > hb["outbound_bytes"]["p95"]:
            p = 12 if new_heavy else 6
            tot += p; pts.append(f"外传量超该小时历史P95+{p}")
        if ratio > hb["upload_download_ratio"]["p99"]:
            p = 18 if new_heavy else 10
            tot += p; pts.append(f"上传/下载比超该小时P99+{p}")
        elif ratio > hb["upload_download_ratio"]["p95"]:
            p = 12 if new_heavy else 6
            tot += p; pts.append(f"上传/下载比超该小时P95+{p}")
        if to_i(r["connection_count"]) <= 2 and ob > 100e6:
            tot += 10; pts.append("罕见单/双连接大外传+10")
        if dur > hb["avg_duration"]["p99"] and ob > 100e6:
            tot += 8; pts.append("长连接大外传(avg_dur>P99)+8")
        if hb["outbound_bytes"]["p50"] <= 0:
            tot += 15; pts.append("主机平时该时段无流量+15")
    return min(tot, 80), pts

def level(r):
    return "CRITICAL" if r >= 80 else "HIGH" if r >= 60 else "MEDIUM" if r >= 40 else "LOW"

# ---------------- main ---------------------------------------------------------
def load_feature_rows(path):
    rows = []
    with open(path) as f:
        header = f.readline().rstrip("\n")
        cols = header.split(",")
        for line in f:
            if not line.strip():
                continue
            rows.append(dict(zip(cols, line.rstrip("\n").split(","))))
    return rows

def load_baseline(path):
    return json_read(path).get("hosts", {})

def json_read(path):
    import json
    with open(path) as f:
        return json.load(f)

def vec(row):
    return [fn(to_f(row[c])) for c, fn in IF_FEATS]

def main(argv):
    args = {a.strip("-").replace("-","_"): v for a, v in zip(argv[::2], argv[1::2])}
    baseline = load_baseline(args["baseline"])
    train    = load_feature_rows(args["if_train"])
    features = load_feature_rows(args["features"])
    hosts    = {h for h in args["hosts"].split(",")} if args.get("hosts") else None

    # train IF on synthetic 14d history (vectorised)
    train_vec = [vec(r) for r in train]
    trees, cmax = fit_forest(train_vec)
    print(f"IF: trees={len(trees)} cmax={cmax:.2f} train_rows={len(train_vec)}")

    wt_all = json_read(args["windows_targets"]) if args.get("windows_targets") else None

    out_rows, summary = [], defaultdict(list)
    for r in features:
        host, wstart = r["host"], r["window_start"]
        if hosts and host not in hosts:
            continue
        ob, connn = to_f(r["outbound_bytes"]), to_i(r["connection_count"])
        hour = 0
        if len(wstart) >= 13:
            hour = int(wstart[11:13])
        if ob <= 0 or connn <= 0:
            out_rows.append([host, wstart, 0, 0.0, "LOW", "-"])
            summary["quiet"].append(0)
            continue
        wt = None
        if wt_all is not None:
            wt = (wt_all.get(host) or {}).get(wstart)
        rule, pts = rule_evidence(host, hour, r, baseline.get(host), wt)
        score, raw = forest_score(trees, cmax, vec(r), len(trees))
        if_pts = int(round(score * 20))
        risk = min(100, rule + if_pts)
        out_rows.append([host, wstart, risk, round(score, 3), level(risk),
                         ",".join(pts) if pts else "no-rule"])
        summary["scored"].append(risk)
    with open(args["out"], "w", newline="") as f:
        import csv
        w = csv.writer(f)
        w.writerow(["host", "window_start", "risk_score", "if_anomaly", "level", "reasons"])
        w.writerows(out_rows)
    print(f"scored {len(summary.get('scored', []))} windows, quiet-skip "
          f"{len(summary.get('quiet', []))}   (outbound=0)")
    print("risk summary of scored: "
          f"n={len(summary['scored'])} max={max(summary['scored']):.0f} "
          f"mean={sum(summary['scored'])/len(summary['scored']):.1f} | "
          f"levels: C={sum(1 for v in summary['scored'] if v>=80)} "
          f"H={sum(1 for v in summary['scored'] if 60<=v<80)} "
          f"M={sum(1 for v in summary['scored'] if 40<=v<60)} "
          f"L={sum(1 for v in summary['scored'] if v<40)}")

if __name__ == "__main__":
    main(sys.argv[1:])