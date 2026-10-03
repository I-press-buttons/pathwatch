# pathwatch HTTP API (internal, used by the embedded UI)

All endpoints except `/healthz` require Basic auth when auth is enabled.
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
  "read_only_config": false
}
```

## Targets

`GET /api/targets`
```json
[{
  "id": 1, "name": "cloudflare", "host": "cloudflare.com",
  "source": "config",                 // config | ui  (ui targets can be deleted from the UI)
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
  "probes": [
    {"id": 3, "type": "icmp-trace", "label": "ICMP trace"},
    {"id": 4, "type": "http", "label": "HEAD https://cloudflare.com/"},
    {"id": 5, "type": "tcp", "label": "TCP :443"}
  ]
}]
```

`POST /api/targets` (create a UI-managed target; 409 on duplicate name, 400 on validation error)
```json
{"name": "my-isp", "host": "example.com", "icmp_interval_ms": 2500,
 "http_url": "https://example.com/", "tcp_port": 443}
```
`http_url`, `tcp_port`, `icmp_interval_ms` are optional. Response: the created target object (as above).

`DELETE /api/targets/{id}` → 204. Only for `source: "ui"`; 403 for config targets.

`POST /api/targets/{id}/pause` / `POST /api/targets/{id}/resume` → 204 (UI targets and config targets; runtime only for config targets).

## Overview sparklines

`GET /api/overview?range=…` → about 60 buckets per target
```json
[{"target_id": 1, "step_ms": 60000,
  "points": [[1759500000000, 12.3, 0.0], [1759500060000, null, null]]}]   // [ts, e2e_avg_ms, e2e_loss_pct]
```

## PingPlotter-style hop grid

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
