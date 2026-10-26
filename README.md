# waf-fp-triage

**Find which WAF rule blocked the request your app never saw.**

You surveyed the app logs first. No 403s. Then you surveyed the WAF metrics per
rule. The times don't match up — until you realize the edge never forwarded
those requests at all. The truth is spread across two telemetry streams, and
nobody has joined them.

Exactly one production incident ago:

- ALB access logs showed **11 × 403** on one API path, all from a single
  source IP — while the application logs showed **zero** 403s anywhere.
- Per-rule CloudWatch WAF metrics showed **no blocks in the same window**
  (metric dimensions and delay make per-rule series sparse and misleading).
- Only the **WAFv2 logging destination** carried the answer: a managed rule
  group terminating the requests — an inner sub-rule, `CrossSiteScripting_BODY`,
  false-positive on a legitimate 11 KB HTML email payload sent from the
  cluster's own egress IP.

This tool joins those streams so the next person gets the answer in one command.

## What it does

| Subcommand | Input | Output |
|---|---|---|
| `alb-scan` | ALB access logs (`.log` / `.log.gz`, file or directory, recursive) | error requests grouped by **source IP / method / path / status** |
| `waf-scan` | WAFv2 log events (saved `filter-log-events` JSON, JSONL, or **live** CloudWatch Logs group) | event summary: terminating rule, the **inner sub-rule** inside managed groups, `matchedData` that tripped it |
| `report` | both of the above | **joined report**: who was stopped, by which rule, with what data — plus WAF events with no ALB counterpart |

## Quickstart (no AWS account needed)

Runs against the included, fully anonymized sample data:

```bash
python -m waf_fp_triage.cli report \
    --alb sample_data/alb_sample.log \
    --waf sample_data/waf_sample.json
```

Expected output (excerpt):

```
ALB non-2xx: 2 ip/method/path/status groups; WAF blocks: 3 events (window ±15 min)

  198.51.100.23  POST /api/send  status=403 x3
      stopped by: aws-common-rules -> CrossSiteScripting_BODY  [condition=XSS, location=BODY]
      matched data: {"type":"email","name":"New login to your account" | doctype html

  203.0.113.44  GET /  status=403 x1
      no WAF block event found (IPSet/absorb rule not logged, or WAF logging gap)
```

The first row is the classic managed-rule false positive. The second row is
the classic "blocked by something that doesn't log" hint.

Other views:

```bash
# raw ALB error groups
python -m waf_fp_triage.cli alb-scan sample_data/alb_sample.log --statuses 403,5xx

# WAF events, blocks only
python -m waf_fp_triage.cli waf-scan --input sample_data/waf_sample.json --action BLOCK
```

## Live mode

Save WAF events yourself (recommended — reproducible and offline):

```bash
aws logs filter-log-events \
    --log-group-name aws-waf-logs-your-acl \
    --region eu-west-2 \
    --start-time $(...) --end-time $(...) \
    --output json > waf-events.json
```

…or query from the CLI directly (requires `pip install boto3`):

```bash
python -m waf_fp_triage.cli waf-scan \
    --log-group aws-waf-logs-your-acl \
    --region eu-west-2 --profile your-sso-profile \
    --client-ip 198.51.100.23 --action BLOCK
```

ALB access logs come from the S3 delivery bucket configured on the load
balancer; pass the local `.log.gz` files (or a directory of them) to any
subcommand.

## Field notes from real incidents

- **The top-level `terminatingRuleId` is not the culprit.** For managed rule
  groups it names the *group* (e.g. `aws-common-rules`). The sub-rule that
  actually fired lives inside `ruleGroupList[#].terminatingRule.ruleId`.
- **Per-rule CloudWatch metrics will mislead you.** Rule-level series are
  sparse, delayed, and depend on which dimensions you query. WAF logging
  (CloudWatch Logs destination) is the authoritative record — enable it
  before the incident, not during.
- **ALB logs carry `actions_executed` fields, but not the terminating rule id
  for WAFv2 in all log formats** — do not rely on the ALB line alone.
- **Scope-down statements matter more than rules.** A common pattern is a
  managed group scoped down with `NotStatement(IPSetReference)`: known-good
  egress IPs skip the group entirely. If a new cluster's NAT egress is missing
  from that IPSet, its traffic eats the managed rules — including false
  positives on HTML bodies. When you stand up a new cluster, adding its
  egress to the trusted set is part of standing it up.
- **Remediation that worked in practice**: adding the internal cluster's
  NAT egress IP to the trusted-egress IPSet (vs. counting the sub-rule down
  for everyone). Verified fix by re-pulling fresh ALB logs: zero new 403s
  after propagation.

## Sample data

Everything in `sample_data/` is synthetic. IPs use RFC 5737 documentation
ranges, hostnames are `docs.example.com`, ARNs and ELB names are dummies. Any
resemblance to real production is coincidence.

## Limitations

- ALB parser targets the standard field layout (see sample file); exotic
  classification variants may need a regex tweak.
- The report joins on exact `client_ip` + path + a time window (±window).
  NAT'd traffic behind the *same* egress is indistinguishable at the edge —
  that is inherent to the data.
- Live mode trusts the local AWS credentials; no credential handling of its own.

## License

MIT — see [LICENSE](LICENSE).
