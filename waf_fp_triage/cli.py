"""Command line interface: alb-scan / waf-scan / report."""

import argparse
import sys
from datetime import datetime, timedelta, timezone

from . import alb, wafl


def _print_rows(rows):
    if not rows:
        print("(no matching rows)")
        return
    headers = ("client_ip", "method", "path", "status", "count", "first_seen", "last_seen")
    print("  ".join(headers))
    for r in rows:
        print("  ".join(str(r.get(h, "-")) for h in headers))


def cmd_alb_scan(args):
    statuses = {int(s) if s.isdigit() else s for s in args.statuses.split(",")}
    prefix = args.path_prefix or None
    if "5xx" in statuses:
        fixed = alb.scan(args.input, statuses=statuses - {"5xx"}, path_prefix=prefix)
        server = alb.scan(args.input, statuses=_server_only(), path_prefix=prefix)
        _print_rows(fixed + server)
        return
    _print_rows(alb.scan(args.input, statuses=statuses, path_prefix=prefix))


def _server_only():
    return {500, 502, 503, 504}


def cmd_waf_scan(args):
    if args.log_group:
        rows = wafl.fetch_live(
            args.log_group, args.region, profile=args.profile,
            since_ms=args.start_time, until_ms=args.end_time, client_ip=args.client_ip,
        )
        rows = [wafl.summarize(e) for e in rows]
    else:
        if not args.input:
            sys.exit("error: provide --input FILE (saved events) or --log-group (live query)")
        rows = wafl.scan(args.input, client_ip=args.client_ip)
    if args.action:
        rows = [r for r in rows if r["action"] == args.action.upper()]
    for r in rows:
        print(r)


def cmd_report(args):
    window = timedelta(minutes=args.window_minutes)
    alb_rows = alb.scan(args.alb, statuses={403, 404, 406, 500, 502, 503, 504},
                        path_prefix=args.path_prefix)
    waf_rows = wafl.summarize_all(args.waf)
    waf_blocks = [r for r in waf_rows if r["action"] == "BLOCK"]

    print(f"ALB non-2xx: {len(alb_rows)} ip/method/path/status groups; "
          f"WAF blocks: {len(waf_blocks)} events "
          f"(window ±{args.window_minutes} min)\n")

    matched = []
    seen_waf = set()
    for a in alb_rows:
        a_dt = datetime.fromisoformat(a["first_seen"])
        links = []
        for i, w in enumerate(waf_blocks):
            if w["client_ip"] != a["client_ip"] or w["uri"] != a["path"]:
                continue
            w_dt = datetime.fromtimestamp(w["ts"], tz=timezone.utc)
            if abs(w_dt - a_dt) <= window:
                links.append((i, w))
        if links:
            seen_waf.update(i for i, _ in links)
            rules_seen = []
            for _, w in links:
                sub = w["sub_rule"]["ruleId"] if w["sub_rule"] else "-"
                data = " | ".join(w["matched_data"] or []) or "-"
                fingerprint = (w["terminating_rule"], sub, data)
                if fingerprint in rules_seen:
                    continue
                rules_seen.append(fingerprint)
                matched.append(
                    f"  {a['client_ip']}  {a['method']} {a['path']}  status={a['status']} x{a['count']}"
                    f"\n      stopped by: {w['terminating_rule']} -> {sub}"
                    f"  [condition={w['condition_type'] or '-'}, location={w['location'] or '-'}]"
                    f"\n      matched data: {data}"
                    f"\n      linked WAF events for this group: {len(links)}"
                )
        else:
            matched.append(
                f"  {a['client_ip']}  {a['method']} {a['path']}  status={a['status']} x{a['count']}"
                "\n      no WAF block event found (IPSet/absorb rule not logged, "
                "or WAF logging gap)"
            )

    print("\n".join(matched) if matched else "  (nothing to join)")

    orphans = [w for i, w in enumerate(waf_blocks) if i not in seen_waf]
    if orphans:
        print("\nWAF blocks with no matching ALB non-2xx (info only):")
        for w in orphans:
            sub = w["sub_rule"]["ruleId"] if w["sub_rule"] else "-"
            print(f"  {w['client_ip']}  {w['method']} {w['uri']}  via {w['terminating_rule']}/{sub}")


def build_parser():
    p = argparse.ArgumentParser(
        prog="waf-fp-triage",
        description="Join ALB access-log anomalies with WAFv2 terminating rules.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("alb-scan", help="group ALB access-log errors by source IP/path")
    a.add_argument("input", help="ALB .log / .log.gz file or directory")
    a.add_argument("--statuses", default="403", help="comma list, e.g. 403,5xx")
    a.add_argument("--path-prefix", default=None, help="only paths starting with this")
    a.set_defaults(func=cmd_alb_scan)

    w = sub.add_parser("waf-scan", help="summarize WAF log events (file or live)")
    w.add_argument("--input", default=None, help="saved WAF events: filter-log-events JSON / JSONL / array")
    w.add_argument("--log-group", default=None, help="live query: CloudWatch Logs group name")
    w.add_argument("--region", default="eu-west-2")
    w.add_argument("--profile", default=None)
    w.add_argument("--start-time", type=int, default=None, help="epoch ms")
    w.add_argument("--end-time", type=int, default=None, help="epoch ms")
    w.add_argument("--client-ip", default=None)
    w.add_argument("--action", default=None, help="filter: BLOCK / ALLOW / COUNT")
    w.set_defaults(func=cmd_waf_scan)

    r = sub.add_parser("report", help="join ALB errors with WAF terminating rules")
    r.add_argument("--alb", required=True, help="ALB log file/dir")
    r.add_argument("--waf", required=True, help="saved WAF events file")
    r.add_argument("--window-minutes", type=int, default=15)
    r.add_argument("--path-prefix", default=None)
    r.set_defaults(func=cmd_report)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
