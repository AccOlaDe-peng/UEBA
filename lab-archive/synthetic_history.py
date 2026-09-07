#!/usr/bin/env python3
"""Generate synthetic Zeek logs for N days of believable baseline traffic.

Purpose: populate the UEBA baseline immediately (P50/P95/P99 per time-of-day,
known-target dictionary) without waiting 24h+ of real observation.

The synthetic host behaviour mirrors observed normal_traffic.sh behaviour:
  - active hours  07-21 weekday: per 5-min cycle -> DNS + web access +
    daily_report upload (1-5MB to backup server) + occasional 10-50MB download
    + one 2GB internal backup per hour
  - quiet hours   00-06: sparse DNS / small heartbeat
  - weekend       scaled-down activity
The exfil target 172.20.69.181 NEVER appears, so a future attack against it
correctly shows new_dst=1 / rare_dst=1.

Outputs (Zeek TSV, compatible with parse_zeek_log() in feature_engine.py):
  <outdir>/conn.log  <outdir>/dns.log  <outdir>/http.log
  <outdir>/targets.json   # per-host dst frequency -> known-target whitelist

Usage: python3 synthetic_history.py [days=14] [seed=42] [outdir=/root/lab/zeek-hist]
"""
import json, os, random, sys, time

DAYS    = int(sys.argv[1]) if len(sys.argv) > 1 else 14
SEED    = int(sys.argv[2]) if len(sys.argv) > 2 else 42
OUTDIR  = sys.argv[3] if len(sys.argv) > 3 else "/root/lab/zeek-hist"
os.makedirs(OUTDIR, exist_ok=True)

random.seed(SEED)
ROUND = 300   # 5-min cycle

VICTIM   = "172.20.69.180"
GATEWAY  = "172.20.69.1"      # DNS resolver
BACKUP   = "172.20.69.182"    # internal backup / known target
EXTERNAL = "172.20.69.181"    # exfil target: MUST NOT appear in history

PUBLIC_HTTPS = ["104.16.132.34", "104.16.133.34", "1.1.1.1", "8.8.8.8",
                "142.250.72.14", "151.101.1.69", "23.54.29.100", "172.67.15.2"]
PUBLIC_HTTP  = ["93.184.216.34", "23.54.29.100"]     # example.com style
DNS_RESOLVERS = [GATEWAY, "8.8.8.8", "1.1.1.1"]
DNS_QUERIES = ["github.com", "pypi.org", "ubuntu.com", "www.baidu.com",
               "api.github.com", "example.com"]

def uid():
    import base64
    b = random.getrandbits(8 * 18).to_bytes(18, "big")
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def conn_row(fields):
    return "\t".join(fields) + "\n"

def active_factor(wday, hour):
    """weekday/weekend + time-of-day activity factor in [0,1]."""
    weekend = wday in (5, 6)
    if weekend:
        return 0.55 if 8 <= hour <= 19 else 0.10
    if 7 <= hour <= 21:
        return 1.0
    if hour in (6, 22, 23):
        return 0.45
    return 0.08   # 00-05

# --- collect rows -----------------------------------------------------------
conn_rows, dns_rows, http_rows = [], [], []
targets = {}      # host -> {dst: count}
now = int(time.time()); now -= now % ROUND
start = (now - DAYS * 86400) // ROUND * ROUND

def bump(host, dst, n=1):
    targets.setdefault(host, {})
    targets[host][dst] = targets[host].get(dst, 0) + n

big_backups = active_cycles = 0
for day in range(DAYS):
    day0 = start + day * 86400
    for cyc in range(288):                       # 288 x 5min
        wstart = day0 + cyc * ROUND                      # window start (epoch)
        t0 = wstart + random.uniform(0, 280)
        # 2GB internal backup ~every 24 windows (~2h), ANY time of day, matching
        # the real normal_traffic.sh cadence (independent of activity profile).
        if random.random() < 1.0 / 24:
            ob = 2147483648
            rb = random.randint(8, 24) * 1024 * 1024
            dur = round(random.uniform(10, 40), 4)
            conn_rows.append(conn_row([
                f"{t0+2.0:.6f}", uid(), VICTIM, "50000", BACKUP, "8000", "tcp",
                "http", f"{dur}", str(ob), str(rb), "SF", "T", "F", "0",
                "ShADadFf", "6", str(ob+140), "5", str(rb+160), "-"]))
            bump(VICTIM, BACKUP)
            big_backups += 1
        hh = time.gmtime(wstart).tm_hour
        wd = time.gmtime(wstart).tm_wday
        act = active_factor(wd, hh)
        if random.random() > act:
            continue
        active_cycles += 1

        # 1) DNS query (udp/53)
        q = random.choice(DNS_QUERIES)
        res = random.choice(DNS_RESOLVERS)
        dns_rows.append("\t".join([
            f"{t0:.6f}", uid(), VICTIM, "54321", res, "53", "udp", "0", "0",
            q, "1", "C_INTERNET", "1", "A", "0", "NOERROR", "F", "F", "T", "T",
            "F", "0", "-", "-", "-"]) + "\n")
        conn_rows.append(conn_row([
            f"{t0:.6f}", uid(), VICTIM, "54321", res, "53", "udp", "dns",
            "0.021", "72", "182", "SF", "T", "F", "0", "Dd", "1", "144",
            "1", "318", "-"]))
        bump(VICTIM, res)

        # 2) web access (small)
        if random.random() < 0.85:
            if random.random() < 0.7:
                dst, port = random.choice(PUBLIC_HTTPS), 443
            else:
                dst, port = random.choice(PUBLIC_HTTP), 80
            ob, rb = random.randint(200, 900), random.randint(1024, 20480)
            dur = round(random.uniform(0.01, 1.2), 4)
            conn_rows.append(conn_row([
                f"{t0+0.2:.6f}", uid(), VICTIM, "44321", dst, str(port),
                "tcp", "https" if port == 443 else "http", f"{dur}", str(ob), str(rb),
                "SF", "T", "F", "0", "ShADadFf", "4", str(ob+96), "6", str(rb+200), "-"]))
            bump(VICTIM, dst)
            http_rows.append("\t".join([
                f"{t0+0.2:.6f}", uid(), VICTIM, "44321", dst, str(port),
                "1", "POST" if port == 443 else "GET",
                "example.com" if port == 80 else "api.github.com",
                "/" if port == 80 else "/v1/data", "-", "curl/7.81.0",
                str(ob), str(random.randint(1024, 20480)), "200", "OK", "-",
                "-", "-", "-", "-", "-", "-", "-", "-"]) + "\n")

        # 3) daily_report upload 1-5MB -> backup server (known target)
        done = False
        for _ in range(2):
            if random.random() < 0.85:
                ob = random.randint(1, 5) * 1024 * 1024
                rej = random.random() < 0.10
                dur = round(random.uniform(0.5, 5.0), 4)
                conn_rows.append(conn_row([
                    f"{t0+0.9:.6f}", uid(), VICTIM, "40000", BACKUP, "8000",
                    "tcp", "http", f"{dur}", str(ob), "1048",
                    "REJ" if rej else "SF", "T", "F", "0",
                    "ShADadfF" if not rej else "Sr", "5", str(ob+120), "4", "2248", "-"]))
                bump(VICTIM, BACKUP)
                done = True
                break
        if done and random.random() < 0.35:
            # 4) 10-50MB download from public
            dst = random.choice(PUBLIC_HTTPS)
            rb = random.randint(10, 50) * 1024 * 1024
            dur = round(random.uniform(2, 40), 4)
            conn_rows.append(conn_row([
                f"{t0+1.3:.6f}", uid(), VICTIM, "44322", dst, "443", "tcp",
                "https", f"{dur}", "180", str(rb), "SF", "T", "F", "0",
                "ShADadFf", "3", "280", str(rb//900), str(rb + random.randint(1000,9000)), "-"]))
            bump(VICTIM, dst)

        # 5) 2GB internal backup moved up: triggered every ~2h regardless of
        #    activity profile (kept here as a comment for readability)

# sanity: EXTERNAL must never appear
assert EXTERNAL not in {d for t in targets.values() for d in t}, "EXTERNAL in history!"

# --- write logs -------------------------------------------------------------
def head(path, fields, types):
    ts = time.strftime("%Y-%m-%d-%H-%M-%S")
    out = [f"#separator \x09", "#set_separator ,", "#empty_field (empty)",
           "#unset_field -", f"#path {path.split('/')[-1].split('.')[0]}",
           f"#open {ts}", "#fields\t" + "\t".join(fields),
           "#types\t" + "\t".join(types)]
    return "\n".join(out) + "\n"

conn_fields = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto",
               "service","duration","orig_bytes","resp_bytes","conn_state",
               "local_orig","local_resp","missed_bytes","history","orig_pkts",
               "orig_ip_bytes","resp_pkts","resp_ip_bytes","tunnel_parents"]
conn_types  = ["time","string","addr","port","addr","port","enum","string",
               "interval","count","count","string","bool","bool","count",
               "string","count","count","count","count","string"]

dns_fields = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto",
              "trans_id","rtt_mode","query","qclass","qclass_name","qtype",
              "qtype_name","rcode","rcode_name","AA","TC","RD","RA","Z",
              "answers","TTLs","rejected"]
dns_types  = ["time","string","addr","port","addr","port","enum","count",
              "count","string","count","string","count","string","count",
              "string","bool","bool","bool","bool","count","vector[string]",
              "vector[count]","bool"]

http_fields = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p",
               "trans_depth","method","host","uri","referrer","user_agent",
               "request_body_len","response_body_len","status_code","status_msg",
               "info_filename","info_tags","username","password","proxied",
               "orig_fuids","orig_filenames","orig_mime_types",
               "resp_fuids","resp_filenames","resp_mime_types"]
http_types  = ["time","string","addr","port","addr","port","count","string",
               "string","string","string","string","count","count","count",
               "string","string","set[string]","string","string","set[string]",
               "vector[string]","vector[string]","vector[string]",
               "vector[string]","vector[string]","vector[string]"]

with open(f"{OUTDIR}/conn.log", "w") as f:
    f.write(head("conn", conn_fields, conn_types))
    f.writelines(conn_rows)
with open(f"{OUTDIR}/dns.log", "w") as f:
    f.write(head("dns", dns_fields, dns_types))
    f.writelines(dns_rows)
with open(f"{OUTDIR}/http.log", "w") as f:
    f.write(head("http", http_fields, http_types))
    f.writelines(http_rows)
with open(f"{OUTDIR}/targets.json", "w") as f:
    json.dump(targets, f, indent=2, sort_keys=True)

print(f"generated: conn={len(conn_rows)} dns={len(dns_rows)} http={len(http_rows)} "
      f"active_cycles={active_cycles} big_backups={big_backups} days={DAYS}")
print(f"EXTERNAL({EXTERNAL}) in history: False (assert ok)")
print(f"wrote -> {OUTDIR}/{{conn,dns,http}}.log, targets.json")