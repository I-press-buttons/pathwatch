# pathwatch HTTP API (internal, used by the embedded UI)

All endpoints except `/healthz` require Basic auth when auth is enabled.
Responses to failed requests: `421` when auth is off and the `Host` header is not a loopback name or IP
or the `public_url` host (DNS-rebinding protection); `429` with `Retry-After` when a client address has
sent too many wrong credentials (nothing is evaluated until the delay has passed).
JSON everywhere. **Timestamps in the API are Unix milliseconds (UTC).** Durations/latencies are
**milliseconds as floats** (3 decimals is plenty). Missing values are `null`.

Range parameters, accepted by every endpoint that returns history:
- `from`, `to`: Unix ms. Default: `to = now`, `from = to - 1h`.
- or `range=1h|6h|24h|7d|30d|90d` (ignored when `from` is given).

Resolution tier is chosen by the server: raw rounds for ranges ≤ 6h, 1-minute rollups ≤ 7d, 1-hour rollups beyond.

## Status

`GET /healthz` → `200 {"ok":true}` (no auth).

`GET /api/status`
```json
{
  "version": "0.1.0", "now": 1759500000000, "uptime_s": 3600,
  "icmp_mode": "raw",                 // raw | dgram | unavailable
  "local_status": "ok",               // ok | down | unknown
  "active_alerts": 1,
  "auth_enabled": true,
  "read_only_config": false,          // true when settings cannot be edited (no settings manager)
  "status_thresholds": {"degraded_loss_pct": 5, "degraded_http_success_pct": 95}
}
```

## Network verdict

`GET /api/network`: one verdict for the whole network over the last 5 minutes, combining the
local-outage detector (gateway), the DNS resolver probes, the first hop outside your network
(ISP) and every running target's `diagnosis`. It answers "is something wrong, and where?".
```json
{
  "severity": "crit",                 // ok | info | warn | crit
  "code": "dns_local_down",
  "where": "dns",                     // local | dns | isp | shared | path | destination | server | null
  "hop": null,                        // the hop the verdict is about, on target_id's path
  "target_id": null,                  // the target whose diagnosis the verdict comes from
  "headline": "Your DNS resolver adguard (192.168.1.5:53) is not answering",
  "detail": "Lookups get no reply, so devices that use it cannot open sites by name. …",
  "segments": [                       // the path from this server outwards
    {"key": "local", "label": "Your network", "state": "ok", "note": "Gateway answers (192.168.1.1)"},
    {"key": "dns", "label": "DNS", "state": "crit", "note": "adguard is failing"},
    {"key": "isp", "label": "ISP", "state": "ok", "note": "First ISP hop answers (hop 2, 203.0.113.1)"},
    {"key": "internet", "label": "Internet", "state": "ok", "note": ""},
    {"key": "destinations", "label": "Destinations", "state": "ok", "note": "3 of 3 targets fine"}
  ],                                  // state: ok | warn | crit | unknown
  "affected": [{"id": 2, "name": "github", "severity": "warn", "where": "path", "headline": "…"}],
  "dns": [{"probe_id": 4, "name": "adguard", "server": "192.168.1.5:53", "local": true,
           "state": "failing", "fail_pct": 100, "avg_ms": null, "last_error": "… i/o timeout"}]
}
```
A DNS probe is `local` when its server is a private, link-local or loopback address. It is
`failing` while a `dns_failure` alert fires or at least half of its lookups (with two or more
samples) failed in the window, and `slow` while a `dns_latency` alert fires. Codes, checked in
this order:

| code | meaning |
|---|---|
| `nothing_monitored` | no target and no DNS probe |
| `gateway_down` | the router (hop 1/2) stopped answering while the targets fail |
| `isp_outage` | every target fails while the router still answers: modem, line or ISP |
| `connection_down` | every target fails and the router's state is unknown |
| `dns_local_down`, `dns_local_upstream`, `dns_local_rejects` | a local resolver does not answer, answers SERVFAIL (its upstream fails), or answers with another error code |
| `local_problem`, `isp_problem`, `dns_problem`, `upstream_problem`, `target_problem` | targets have problems; the verdict follows the most fundamental location among their diagnoses (your network, ISP, DNS, a shared hop beyond the ISP, then single routes or servers) and lists the affected targets |
| `dns_public_failing`, `dns_slow` | a resolver outside your network fails, or a resolver is slow, while the targets are fine |
| `nodata` | no target has recent results |
| `ok` | nothing wrong (suggests a DNS probe for your own resolver when there is none) |

## Prometheus metrics

`GET /metrics` (opt-in: `metrics.enabled: true`, otherwise `404`). Same auth and middleware as `/api/*`.
Prometheus text format 0.0.4 (`Content-Type: text/plain; version=0.0.4; charset=utf-8`). Values are over
the last 5 minutes of the 1-minute rollups; seconds and 0..1 ratios; no sample is emitted without data.
Label values are escaped (`\\`, `\"`, `\n`). Hops are labelled by `ttl`, never by address.

| Metric | Labels |
|---|---|
| `pathwatch_target_up`, `_paused`, `_loss_ratio`, `_rtt_avg_seconds`, `_rtt_min_seconds`, `_rtt_max_seconds`, `_rtt_p95_seconds`, `_jitter_seconds`, `_mos`, `_hops` | `target`, `host` |
| `pathwatch_hop_loss_ratio`, `pathwatch_hop_rtt_avg_seconds` | `target`, `ttl` |
| `pathwatch_probe_total_seconds`, `_dns_seconds`, `_connect_seconds`, `_tls_seconds`, `_ttfb_seconds`, `_transfer_seconds`, `_error_ratio`, `_http_status`, `_cert_expiry_timestamp_seconds` | `target`, `probe`, `type` |
| `pathwatch_alerts_active`, `pathwatch_outbox_pending` | none |
| `pathwatch_build_info` | `version` (value 1) |

`target_up`/`target_loss_ratio` use the destination (ICMP, else the TCP or HTTP probe); they are omitted
when only the last responding hop is available (its loss is often rate limiting). DNS probes are not exported.

## Targets

`GET /api/targets`
```json
[{
  "id": 1, "name": "cloudflare", "host": "cloudflare.com",
  "host_kind": "hostname",            // hostname | ipv4 | ipv6
  "source": "config",                 // config | ui  (ui targets can be deleted from the UI)
  "overridden": false,                // a config-file target whose settings were edited in the UI
  "active": true,
  "status": "ok",                     // ok | degraded | alerting | silenced | nodata | learning
  "resolved_ip": "104.16.132.229",
  "icmp_unresponsive": false,
  "icmp_interval_ms": 2000,
  "last_round": 1759500000000,
  "summary": {                        // over the last 5 minutes
    "e2e_rtt_ms": 12.3, "e2e_p95_ms": 15.1, "e2e_loss_pct": 0.0, "jitter_ms": 0.8,
    "mos": 4.39,                      // ITU-T G.107 simplified E-model, 1..4.5
    "hop_count": 11,
    "http_total_ms": 85.2, "http_success_pct": 100.0,
    "cert_not_after": 1767225600000,  // null if no HTTPS probe
    "active_alerts": 0
  },
  "diagnosis": {                      // plain-language verdict, also over the last 5 minutes
    "severity": "warn",               // ok | info | warn | crit
    "code": "path_shared",            // see below
    "where": "shared",                // local | isp | shared | path | destination | server | dns | null
    "hop": 3,                         // the hop the finding is about, or null
    "headline": "Loss or delay starts at hop 3 (core1.isp.example, 203.0.113.1), which other targets share",
    "detail": "All 4 other targets through this hop are affected too, so the problem is probably at AS64500 (Example ISP) rather than at one destination."
  },
  "probes": [
    {"id": 3, "type": "icmp-trace", "label": "ICMP trace"},
    {"id": 4, "type": "http", "label": "HEAD https://cloudflare.com/"},
    {"id": 5, "type": "tcp", "label": "TCP :443"}
  ]
}]
```

`diagnosis` explains the status from what the hop classifier, the probes and the alert engine
know, checked from the most fundamental cause to the most specific. Codes:

| code | meaning |
|---|---|
| `ok`, `learning` | nothing wrong (`learning`: latency baselines are still being collected) |
| `ok_rate_limited` | nothing wrong; `hop` is the first router that drops pings while the path beyond it is clean (ICMP rate-limiting) |
| `paused`, `removed`, `nodata` | not measured right now (`detail` says why when it can) |
| `local_outage` | the gateway stopped answering, or every target fails at once |
| `path_local`, `path_isp`, `path_shared`, `path` | the hop classifier found a real degradation starting at `hop`: inside your network, at your ISP (the first hop outside your network, a carrier-grade NAT address, or a hop in that hop's AS), at a hop other degraded targets share, or on this target's route only |
| `destination` | only the destination is degraded |
| `e2e_loss` | end-to-end loss above the status threshold; with a `hop` when every hop from it to the destination loses pings (the HTTP/TCP probes may still succeed) |
| `destination_loss` | only the destination drops pings (with clean HTTP/TCP probes it probably limits its replies) |
| `http_failure`, `tcp_failure` | the probes fail; `where` follows the error (an HTTP status or refused connection: `server`; a name that does not resolve: `dns`, naming the failing local resolver when a DNS probe of it fails too; a timeout with a clean path: `server`) |
| `http_slow`, `http_slow_server`, `http_slow_network`, `http_slow_dns`, `http_slow_transfer` | an `http_latency` alert is firing, attributed to the HTTP phase that grew the most against the 6 hours before the alert |
| `cert_expiry`, `alert`, `degraded` | another active alert, or a status threshold without a more specific cause |

`severity` follows the status: `crit` while an alert fires, `warn` when degraded or silenced.

### Target definitions

A target definition is the JSON form of a `targets:` entry of the config file. Durations are
milliseconds (`*_ms`); a missing or zero value inherits the defaults, a missing `retries`
inherits `defaults.retries`.

```json
{
  "name": "my-isp",
  "host": "example.com",              // FQDN (trailing dot allowed), short name, IPv4 or IPv6 ("[...]" accepted)
  "max_hops": 30, "path_rediscovery_ms": 300000,
  "probes": [
    {"type": "icmp-trace", "interval_ms": 2000, "timeout_ms": 2000},
    {"type": "http", "url": "https://example.com/", "method": "GET", "expect_status": [200, 301],
     "interval_ms": 30000, "timeout_ms": 10000, "retries": 1,
     "follow_redirects": false, "insecure_skip_verify": false},
    {"type": "tcp", "port": 443, "interval_ms": 10000, "timeout_ms": 5000, "retries": 2}
  ],
  "alerts": {                         // per-target alert settings (rule names)
    "disable": ["route"],
    "override": {"end-loss": {"threshold_pct": 10, "window_ms": 600000}}
  }
}
```

Hosts are validated and normalized (lower-cased, IPv6 compressed, brackets removed). A URL or a
`host:port` is rejected with a message saying what to change. `retries` (0–10) applies to HTTP and
TCP probes; ICMP hop probes never retry.

`POST /api/targets` creates a UI-managed target from a definition (201, the target object; 409 on
a duplicate name, 400 on a validation error, including a definition with more than 16 probes or
a create when config-file and UI targets together already number 200). The simple form of earlier versions is still accepted:
```json
{"name": "my-isp", "host": "example.com", "icmp_interval_ms": 2500,
 "http_url": "https://example.com/", "tcp_port": 443}
```
Unknown fields are rejected.

`GET /api/targets/{id}/config` → `{"id", "source", "overridden", "target": <definition>}`. The
definition is normalized for editing: an implied icmp-trace probe is listed, target-level
intervals and retries are moved onto the probes, and alert settings keyed by rule type are
expanded to rule names. Literal HTTP probe header values are returned as the placeholder
`********`; values that are `${PATHWATCH_PROBE_*}` references are returned as written. Send the
placeholder back in `PUT` to keep the stored value for the same probe (method + URL) and header
name; if the probe's URL or method changed, the request is rejected (400) and the value must be
entered again. The placeholder is rejected when creating a target.

`PUT /api/targets/{id}` with a definition → 200, the target object. Applies immediately. A UI
target may be renamed (its history is kept). A config-file target keeps its name (400 on a
rename); its edited definition is stored in the database and overrides the file until reverted.
A definition with more than 16 probes is refused with 400. Changing a probe's identity (HTTP method or URL, TCP port) starts a new history for that probe;
intervals, timeouts and retries do not.

`DELETE /api/targets/{id}/override` → 204: a config-file target uses its file definition again
(409 if it has no UI edits).

`DELETE /api/targets/{id}` → 204. Only for `source: "ui"`; 403 for config targets.

`POST /api/targets/{id}/pause` / `POST /api/targets/{id}/resume` → 204 (UI targets and config targets; runtime only for config targets).

`GET /api/resolve?host=…` validates a host as a target would and resolves a hostname with the
system resolver:
```json
{"valid": true, "host": "example.com.", "kind": "hostname", "addresses": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:34"]}
{"valid": true, "host": "nas.lan", "kind": "hostname", "addresses": [], "resolve_error": "no such host"}
{"valid": false, "error": "invalid host \"example.com:443\": remove the port (:443); ..."}
```

## Settings

Settings edited in the UI are stored in the database and replace the matching section of the
config file until reverted. Changes apply immediately (no restart).

`GET /api/settings`
```json
{
  "defaults":   {"source": "file", "value": {...}, "file": {...}},
  "status":     {"source": "ui",   "value": {"degraded_loss_pct": 2, "degraded_http_success_pct": 99}, "file": {...}},
  "alerts":     {"source": "file", "value": {"rules": [...], "cooldown_ms": 1800000, "clear_ratio": 0.7}, "file": {...}},
  "dns_probes": {"source": "file", "value": [{"name": "home-resolver", "server": "192.168.1.1:53", "query": "example.com", "record": "A"}], "file": [...]},
  "maintenance_windows": {"source": "ui", "value": [{"name": "nightly", "days": ["mon"], "start": "02:00", "end": "03:00", "timezone": "UTC"}], "file": [...]},
  "notify":     {"source": "ui", "value": {"webhook": {"url": "********", "preset": "discord"}, "email": null, "outbox_max_age_ms": 86400000}, "file": {...}},
  "heartbeat":  {"source": "file", "value": {"url": "", "interval_ms": 300000}, "file": {...}},
  "retention":  {"source": "file", "value": {"raw_retention_ms": 604800000, "rollup_1m_retention_ms": 7776000000, "rollup_1h_retention_ms": 0}, "file": {...}},
  "enrich":     {"source": "file", "value": {"reverse_dns": true}, "file": {...}},
  "notify_env_prefix": "PATHWATCH_NOTIFY_",
  "dns_query_presets": ["google.com", "youtube.com", "facebook.com", ...],
  "channels": {"webhook": true, "email": false},
  "rule_types": ["cert_expiry", "dns_failure", ...],
  "max_retries": 10
}
```
`source` is `ui` when the section was edited in the UI, `file` otherwise; `file` is what a revert
restores. Value shapes:
- `defaults`: `icmp_interval_ms`, `icmp_timeout_ms`, `tcp_interval_ms`, `tcp_timeout_ms`,
  `http_interval_ms`, `http_timeout_ms`, `dns_interval_ms`, `dns_timeout_ms`,
  `path_rediscovery_ms`, `max_hops`, `retries` (0 = built-in default, except `retries`), and
  `dns_query`: the name DNS probes without their own query look up (blank = `google.com`).
- `alerts.rules[]`: `name`, `type`, `enabled`, `notify`, and the parameters of the type:
  `consecutive`, `metric`, `multiplier`, `min_delta_ms`, `sustain_ms`, `baseline_window_ms`,
  `min_baseline_ms`, `threshold_pct`, `window_ms`, `warn_before_ms`.
- `dns_probes[]`: `name`, `server`, `query`, `record`, `interval_ms`, `timeout_ms`, `retries`. A
  blank or missing `query` uses `defaults.dns_query`.

`dns_query_presets` lists the popular names the UI offers as DNS queries.
- `maintenance_windows[]`: `name`, `days` (`mon`..`sun`), `start` and `end` (`HH:MM`; an end at
  or before the start crosses midnight), `timezone` (IANA name, default UTC).
- `notify`: `webhook` and `email` (`null` = channel off) and `outbox_max_age_ms`.
  `webhook`: `url` or `url_env`, `preset` (`generic`, `discord`, `slack`, `ntfy`), `headers`,
  `body_template`. `email`: `smtp_host`, `smtp_port`, `tls` (`starttls`, `tls`, `none`), `from`,
  `to[]`, and either `username`/`password` or `username_env`/`password_env`.
  Secrets are never returned: a literal webhook URL, literal header values and the SMTP password
  come back as `"********"`. Sending `"********"` back keeps the saved value, but only while the
  channel delivers to the same place (same webhook URL or variable; same SMTP host and port);
  otherwise the request fails and the secret must be entered again. Environment references
  (`url_env`, `username_env`, `password_env`, `${NAME}` in header values) must start with
  `PATHWATCH_NOTIFY_`, except the ones the config file already uses for the same destination.
- `heartbeat`: `url` (empty = off), `interval_ms`.
- `retention`: `raw_retention_ms` (at least 1h), `rollup_1m_retention_ms`,
  `rollup_1h_retention_ms`; 0 keeps data forever. A shorter period deletes older data at the next
  hourly cleanup.
- `enrich`: `reverse_dns`.

Server paths and process settings (`listen`, `public_url`, `auth`, `tls`, `log`, `storage.path`,
`probing.icmp_mode`, `enrich.asn_db`) are only set in the config file.

`PUT /api/settings/{section}` with the section's value → 200 and the
full settings (as `GET`). 400 with every validation problem (for example a rule a target still
refers to, or more than 50 DNS probes). Unknown fields are rejected.

`DELETE /api/settings/{section}` → 200 and the full settings: the section comes from the config
file again.

## Overview sparklines

`GET /api/overview?range=…` → about 60 buckets per target
```json
[{"target_id": 1, "step_ms": 60000,
  "points": [[1759500000000, 12.3, 0.0], [1759500060000, null, null]]}]   // [ts, e2e_avg_ms, e2e_loss_pct]
```

## Hop grid

`GET /api/targets/{id}/hops?range=…`: aggregates per TTL over the range (path at the end of the range)
```json
{
  "target_id": 1, "path_id": 7, "resolved_ip": "104.16.132.229",
  "from": 1759496400000, "to": 1759500000000,
  "hops": [{
    "ttl": 1, "address": "192.168.1.1", "hostname": "router.lan",
    "asn": null, "as_name": null,
    "responders": 1,                  // >1 = load-balanced hop, list in "alt_addresses"
    "alt_addresses": [],
    "sent": 1800, "lost": 0, "loss_pct": 0.0,
    "min_ms": 0.4, "avg_ms": 0.7, "max_ms": 3.1, "cur_ms": 0.6, "p95_ms": 1.2, "jitter_ms": 0.1,
    "classification": "ok",           // ok | rate_limited | degraded | no_reply | destination
    "is_destination": false
  }]
}
```
Non-responding TTLs are included with `address: null`, `classification: "no_reply"`.

## Path timeline (heatmap)

`GET /api/targets/{id}/timeline?range=…&buckets=300`
```json
{
  "from": 1759496400000, "to": 1759500000000, "step_ms": 12000, "resolution": "raw",
  "ttls": [1, 2, 3],
  "labels": [{"ttl": 1, "address": "192.168.1.1", "hostname": "router.lan", "classification": "ok"}],
  "rtt":  [[0.7, 0.6, null], [5.1, 5.3, 5.2], [11.9, null, 12.1]],   // [ttl index][bucket] avg ms
  "loss": [[0, 0, null],     [0, 0, 0],       [0, 100, 0]],          // [ttl index][bucket] loss %
  "gaps": [[1759497000000, 1759497300000]],                           // monitor gaps: "no data"
  "events": [{"kind": "route_change", "ttl": null, "from": 1759498000000, "to": null, "details": {}},
             {"kind": "rate_limited", "ttl": 5, "from": 1759496400000, "to": null, "details": {}},
             {"kind": "alert", "ttl": null, "from": 1759499000000, "to": 1759499300000,
              "details": {"rule": "http-slow", "alert_id": 12}}]
}
```
`null` in `rtt` means no successful reply in that bucket. `null` in `loss` means no probes were sent (gap).

## Hop latency series (graph for a selected hop, default = destination)

`GET /api/targets/{id}/series?ttl=11&range=…&buckets=300`. Omit `ttl` to get the destination (e2e).
```json
{"ttl": 11, "step_ms": 12000,
 "points": [[1759496400000, 12.1, 11.8, 14.0, 0.0]]}     // [ts, avg_ms, min_ms, max_ms, loss_pct]
```

## HTTP / TCP / DNS probe series

`GET /api/targets/{id}/probes?range=…&buckets=300`
```json
{
  "http": [{"probe_id": 4, "label": "HEAD https://cloudflare.com/", "cert_not_after": 1767225600000,
            "points": [[1759496400000, 1.2, 10.4, 21.0, 35.5, 0.4, 68.5, 100.0]]}],
            // [ts, dns, connect, tls, ttfb, transfer, total (ms avg), success_pct]
  "tcp":  [{"probe_id": 5, "label": "TCP :443",
            "points": [[1759496400000, 10.3, 0.0]]}]   // [ts, connect_ms avg, fail_pct]
}
```

`GET /api/dns?range=…&buckets=300`
```json
[{"probe_id": 9, "name": "home-resolver", "server": "192.168.1.1:53", "query": "example.com",
  "points": [[1759496400000, 3.2, 0.0]]}]                 // [ts, rtt_ms avg, fail_pct]
```

## Export (file download)

`GET /api/targets/{id}/export?from=…&to=…&format=csv|json&kind=hops|probes[&res=1m|1h]`

Rollup rows of one target as an attachment (`Content-Disposition: attachment; filename="pathwatch-<target>-<kind>-<from>-<to>.csv|json"`), streamed. Range parameters as above (default last hour, at most 400 days). `format` defaults to `csv`, `kind` to `hops`.
Resolution: 1-minute buckets up to 7 days, 1-hour beyond, unless `res` is given. Rows are only produced for buckets with data. Invalid parameters, and a request that would return more than 250,000 rows (the error says how many), answer `400 {"error": …}` before any data is sent; narrow the range or use `res=1h`.

`kind=hops` columns: `bucket_start` (RFC 3339 UTC), `bucket_start_ms`, `ttl`, `address`, `hostname`, `asn`, `as_name` (the responder of the path version current at the end of the range, where known), `sent`, `lost`, `loss_pct`, `rtt_min_ms`, `rtt_avg_ms`, `rtt_max_ms`, `jitter_ms`, `rtt_p95_ms` (empty above about 60,000 rows, where histograms are skipped).
`kind=probes` columns (HTTP and TCP probes of the target): `bucket_start`, `bucket_start_ms`, `probe_id`, `probe`, `type`, `samples`, `errors`, `error_pct`, `dns_avg_ms`, `connect_avg_ms`, `tls_avg_ms`, `ttfb_avg_ms`, `transfer_avg_ms`, `total_min_ms`, `total_avg_ms`, `total_max_ms`, `total_p95_ms`.

CSV: UTF-8, header row, encoding/csv quoting, empty cell = no value. Text cells starting with `=`, `+`, `-`, `@`, tab or CR get a leading `'` (formula-injection guard; hostnames come from reverse DNS).
JSON: `{"target_id", "target", "kind", "resolution": "1m0s", "from", "to", "row_count", "rows": [{<column>: value, …}]}` with `null` for missing values; text is exported unmodified.

## Report data

`GET /api/targets/{id}/report?from=…&to=…` (range parameters as above)
```json
{"target": {"id": 1, "name": "cloudflare", "host": "cloudflare.com"},
 "from": 1759496400000, "to": 1759582800000, "generated_at": 1759582800000, "resolution": "1m",
 "summary": {"source": "icmp",            // icmp | tcp | last_hop | http | none: where the end-to-end series comes from
   "samples": 17280, "availability_pct": 99.2, "loss_pct": 0.8, "avg_ms": 12.3, "p95_ms": 21.0,
   "jitter_ms": 1.1, "mos": 4.31,
   "http": [{"probe_id": 4, "label": "HEAD https://cloudflare.com/", "type": "http", "samples": 2880, "errors": 3, "success_pct": 99.9, "avg_ms": 68.5}],
   "tcp":  [{"probe_id": 5, "label": "TCP :443", "type": "tcp", "samples": 8640, "errors": 0, "success_pct": 100.0, "avg_ms": 10.3}]},
 "incidents": [{"source": "alert",         // alert | event
   "id": 12, "kind": "final_hop_loss",     // rule type of an alert; event kinds: degraded | icmp_unresponsive | local_outage
   "rule": "dest-loss", "severity": "critical",   // critical | warning | info
   "state": "resolved", "message": "…", "started_at": 1759499000000, "ended_at": 1759499300000, "ongoing": false,
   "duration_ms": 300000,                  // an ongoing incident lasts until the end of the range
   "ttl": null,
   "origin": {"ttl": 7, "address": "203.0.113.9", "hostname": "core1.isp.example", "asn": 64500, "as_name": "Example ISP",
              "reason": "loss", "loss_pct": 42.0, "avg_ms": 18.2, "baseline_max_ms": 25.0, "classification": "degraded"},
   "probes": [{"probe_id": 5, "label": "TCP :443", "type": "tcp", "samples": 30, "errors": 12, "success_pct": 60.0, "avg_ms": 11.0}]}],
 "truncated": false,                       // true when more than 200 incidents were in the range
 "gaps": [{"from": 1759510000000, "to": 1759510300000, "duration_ms": 300000}],      // no data, not loss
 "path_changes": [{"at": 1759520000000, "from_ip": "192.0.2.1", "to_ip": "192.0.2.2", "resolved_ip": "192.0.2.2"}]}
```
Incidents are the target's non-suppressed alerts and its `degraded`, `icmp_unresponsive` and `local_outage` events that overlap the range, oldest first. `origin` is the earliest hop where loss (above 5%) or latency (above its baseline band, from the six hours before the incident) starts while every hop and probe after it is degraded too, from `analyze.Classify` over the incident window. It is `null` when no hop qualifies (a hop that degrades alone is ICMP rate limiting) and for kinds that are not about delivery (certificate, route change, local outage, ICMP-unresponsive). `probes` is the HTTP/TCP result during the incident. Missing values are `null`.

## Alerts and events

`GET /api/alerts?limit=100&target_id=…`
```json
[{"id": 12, "target_id": 1, "target_name": "cloudflare", "rule": "http-slow", "rule_type": "http_latency",
  "state": "resolved",                // firing | resolved | suppressed
  "suppressed_reason": null,          // silence | maintenance | local_outage | cooldown | null
  "started_at": 1759499000000, "ended_at": 1759499300000,
  "value": 412.0, "peak_value": 530.1, "baseline": 85.0, "message": "HTTP total 412ms vs baseline 85ms",
  "deliveries": [{"channel": "webhook", "status": "delivered", "attempts": 1, "last_error": null}]}]
```
`status` values: queued | delivered | retrying | failed | expired.

`GET /api/events?target_id=1&range=…` → `[{"id", "target_id", "kind", "ttl", "from", "to", "details"}]`
Kinds: `route_change`, `rate_limited`, `icmp_unresponsive`, `gap`, `local_outage`.

## Silences

`GET /api/silences` → `[{"id", "target_id", "rule", "starts_at", "ends_at", "reason", "source"}]`
(`source`: ui | maintenance). Includes active and upcoming silences, plus the active maintenance windows.

`POST /api/silences` with `{"target_id": null, "rule": null, "duration_ms": 3600000, "reason": "router upgrade"}`
(or `starts_at`/`ends_at`). Requires `Content-Type: application/json`. Response: the silence.

`DELETE /api/silences/{id}` → 204.

## Notification channels

Channels are configured in the config file only (`alerts.notify`); the API shows their state and
sends test notifications. Webhook URLs, header values and SMTP credentials are never returned;
for environment variables only whether they are set.

`GET /api/channels`
```json
[{"name": "webhook", "configured": true, "active": true,
  "summary": "discord preset · URL from $PATHWATCH_WEBHOOK_URL",
  "warnings": [],                     // e.g. "environment variable PATHWATCH_WEBHOOK_URL is empty, …"
  "last_delivery": {"alert_id": 12, "status": "delivered", "attempts": 1, "at": 1759499300000, "error": null},
  "last_test": {"ok": true, "error": null, "at": 1759500000000, "duration_ms": 312.4}},
 {"name": "email", "configured": false, "active": false, "summary": "", "warnings": [], "last_delivery": null, "last_test": null}]
```
`active` is false when the configuration was rejected at startup. `last_delivery` is the newest
outbox row of the channel; `last_test` is kept in memory until a restart.

`POST /api/channels/{webhook|email}/test` sends a test notification right away, bypassing the
outbox (nothing is stored or retried). It is a one-shot event: `state: "event"`, `rule_type:
"test"`, `rule: "test-notification"`, `alert_id: 0`, no target, and a link to the alerts page when
`public_url` is set. Response `200` with the outcome, also when delivery failed:
```json
{"ok": false, "error": "webhook returned HTTP 400", "at": 1759500000000, "duration_ms": 87.1}
```
`404` for an unknown channel, `409` when it is not configured, `429` with `Retry-After` within 10 s
of the previous test of the same channel.

## Live stream (SSE)

`GET /api/stream`: `text/event-stream`, a `: ping` comment every 15s. Events:

- `event: round` →
  `{"target_id":1,"ts":1759500000000,"hops":[{"ttl":1,"address":"192.168.1.1","rtt_ms":0.6},{"ttl":2,"address":null,"rtt_ms":null}]}`
- `event: probe` → `{"target_id":1,"probe_id":4,"type":"http","ts":…,"ok":true,"total_ms":68.5}`
  (DNS probes have `target_id: null`)
- `event: alert` → an alert object as in `/api/alerts`
- `event: targets` → `{}` (the target list changed; refetch `/api/targets`)

## Errors

Non-2xx responses carry `{"error": "human readable message"}`.
