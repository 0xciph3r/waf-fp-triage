"""Parse AWS ALB access logs and group non-2xx responses by source IP and path.

Handling mirrors what actually matters during triage:
- .log and .log.gz files, single files or whole directories (recursive)
- the common ALB log field layout (see sample_data/alb_sample.log)
- missing/unidentifiable backends (target "-", times "-1"), i.e. requests the
  ALB never forwarded -- which is exactly where edge-blocked requests live
"""

import gzip
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Standard ALB access-log layout:
#   type time elb client:port target:port req_time target_time resp_time
#   status - received sent "request" "user-agent" ...
# The target/process fields sit between client and status; times may be "-1"
# when no backend was ever reached.
ALB_RE = re.compile(
    r"^(?P<type>\S+)\s+(?P<ts>\S+)\s+(?P<elb>\S+)\s+"
    r"(?P<client_ip>\S+):\d+\s+"
    r"(?P<target>\S+)\s+(?P<rt>\S+)\s+(?P<tt>\S+)\s+(?P<pt>\S+)\s+"
    r"(?P<status>\d{3})\s+(?P<extra>\S+)\s+"
    r"(?P<rbytes>\d+)\s+(?P<sbytes>\d+)\s+"
    r"\"(?P<request>[^\"]+)\"\s+\"(?P<ua>[^\"]*)\""
)

REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+)\s+\S+://(?P<host>[^/\s:]+)(?::\d+)?(?P<path>/[^ ]*)\s+\S+$")


def parse_ts(raw: str) -> datetime:
    """ALB timestamps look like 2026-10-25T01:02:19.655442Z."""
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def split_request(request: str) -> dict:
    m = REQUEST_RE.match(request)
    if m:
        return {"method": m["method"], "host": m["host"], "path": m["path"]}
    # fall back to a bare "METHOD /path HTTP/x" form
    parts = request.split()
    if len(parts) >= 2:
        return {"method": parts[0], "host": "?", "path": parts[1]}
    return {"method": "?", "host": "?", "path": "?"}


def iter_lines(path: Path):
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file():
                yield from iter_lines(child)
        return
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            yield from fh
    except OSError as exc:  # unreadable file: skip, triage continues
        print(f"[warn] skipping {path}: {exc}", file=__import__("sys").stderr)


def load_records(path: str | Path):
    """Yield parsed records for a file or directory of ALB logs."""
    for line in iter_lines(Path(path)):
        m = ALB_RE.match(line)
        if not m:
            continue
        req = split_request(m["request"])
        try:
            ts = parse_ts(m["ts"])
        except ValueError:
            continue
        yield {
            "ts": ts,
            "client_ip": m["client_ip"],
            "status": int(m["status"]),
            "method": req["method"],
            "host": req["host"],
            "path": req["path"],
            "user_agent": m["ua"],
            "received_bytes": int(m["rbytes"]),
            "sent_bytes": int(m["sbytes"]),
        }


def scan(path, statuses=(403,), path_prefix=None):
    """Count matching records per (ip, method, path, status)."""
    counts = Counter()
    first, last = {}, {}
    for rec in load_records(path):
        if statuses and rec["status"] not in statuses:
            continue
        if path_prefix and not rec["path"].startswith(path_prefix):
            continue
        key = (rec["client_ip"], rec["method"], rec["path"], rec["status"])
        counts[key] += 1
        iso = rec["ts"].isoformat()
        if key not in first or iso < first[key]:
            first[key] = iso
        if key not in last or iso > last[key]:
            last[key] = iso
    out = []
    for k, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        ip, method, path_, status = k
        out.append({
            "client_ip": ip, "method": method, "path": path_, "status": status,
            "count": n, "first_seen": first[k], "last_seen": last[k],
        })
    return out
