"""Read AWS WAFv2 logging events and surface the terminating rule.

Two sources, one record shape:
- saved files (aws logs filter-log-events output, JSONL, or a bare array)
- live queries against the log group (requires boto3)

The interesting field is not the top-level terminatingRuleId (that is the
customer rule grouping, e.g. an "aws-common-rules" managed group) but the
inner rule inside ruleGroupList (e.g. CrossSiteScripting_BODY) plus the
matchedData that tripped it.
"""

import json
from pathlib import Path


def _parse_message(raw):
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def load_events(path: str | Path):
    """Load WAF log events from a saved JSON file/JSONL."""
    events = []
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict) and "events" in data:          # filter-log-events
        blobs = data["events"]
        events = [_parse_message(e.get("message", e)) for e in blobs]
    elif isinstance(data, list):                              # bare array
        events = [_parse_message(e) for e in data]
    else:                                                     # JSONL
        events = [_parse_message(line) for line in text.splitlines()]
    return [e for e in events if e]


def _inner_terminating(message):
    """The sub-rule inside the managed group that fired, if any."""
    for group in message.get("ruleGroupList") or []:
        term = group.get("terminatingRule") or {}
        if term.get("ruleId"):
            return {"ruleGroupId": group.get("ruleGroupId"), "ruleId": term["ruleId"]}
    return None


def summarize(event):
    """Reduce a raw WAF log event to the triage-relevant fields."""
    details = event.get("terminatingRuleMatchDetails") or []
    matched = details[0] if details else {}
    http = event.get("httpRequest") or {}
    return {
        "ts": event.get("timestamp"),
        "action": event.get("action"),
        "terminating_rule": event.get("terminatingRuleId"),
        "terminating_rule_type": event.get("terminatingRuleType"),
        "sub_rule": _inner_terminating(event),
        "condition_type": matched.get("conditionType"),
        "location": matched.get("location"),
        "matched_data": [
            s if len(s) <= 60 else s[:57] + "..."
            for s in (matched.get("matchedData") or [])[:2]
        ],
        "client_ip": http.get("clientIp"),
        "method": http.get("httpMethod"),
        "uri": http.get("uri"),
    }


def summarize_all(path):
    return [summarize_file := [summarize(e) for e in load_events(path)]][0]


def fetch_live(log_group, region, profile=None, since_ms=None, until_ms=None, client_ip=None):
    """Query an active WAFv2 logging destination (CloudWatch Logs group).

    boto3 is imported lazily so saved-file workflows need no AWS SDK.
    """
    import boto3

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    logs = session.client("logs", region_name=region)
    kwargs = {"logGroupName": log_group, "logStreamNamePrefix": ""}
    if since_ms:
        kwargs["startTime"] = int(since_ms)
    if until_ms:
        kwargs["endTime"] = int(until_ms)
    if client_ip:
        kwargs["filterPattern"] = client_ip
    out, token = [], None
    while True:
        call = dict(kwargs)
        if token:
            call["nextToken"] = token
        resp = logs.filter_log_events(**call)
        out.extend(_parse_message(e.get("message")) for e in resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            break
    return [e for e in out if e]


def scan(path, client_ip=None, block_only=True):
    rows = summarize_all(path)
    if client_ip:
        rows = [r for r in rows if r["client_ip"] == client_ip]
    if block_only:
        rows = [r for r in rows if r["action"] == "BLOCK"]
    return rows
