# Network Path Monitor: Project Spec

A self-hosted, always-on network performance monitor comparable in scope to commercial path-analysis tools. It continuously traces the path to a handful of destinations, records per-hop latency and loss, and also measures real HTTP/HTTPS request timing so that ICMP rate limiting on intermediate routers doesn't cause false alarms. A browser dashboard shows history, and webhook and email alerts flag anomalies.

Project name: `pathwatch`.

> **Revision 2 (2026-10-03).** This version folds in a spec review: ambiguities resolved, missing decisions made, and scope adjusted. Changes from the original are summarized in [Changelog vs. original spec](#changelog-vs-original-spec) at the end.

## Goals

- Personal tool first, but built cleanly enough to publish as a public GitHub project.
- Runs 24/7 as a single binary, no runtime to install. **Primary deployment is Docker on a NAS or home server (Linux, amd64/arm64)**; native Linux and Windows are also supported.
- Per-hop timeline (latency and loss over time) for each target.
- HTTP/HTTPS probes with phase timing (DNS, TCP connect, TLS, TTFB, transfer, total) as the ground truth for "is anyone actually affected".
- Show hop view and HTTP view side by side on one time axis so the two can be correlated.
- Long-term history in SQLite with continuous aggregation and automatic downsampling.
- Alerting via webhook and email, tuned to avoid false positives from router ICMP deprioritization, and able to deliver alerts about outages after connectivity returns.
- Browser dashboard, embedded in the binary.

## Non-goals (for now)

- Multi-user accounts, SSO, or hosted/SaaS operation.
- Monitoring dozens or hundreds of targets. Design for a handful (roughly 3 to 10).
- Multiple vantage points / distributed agents reporting to a central server.
- A native desktop GUI.
- Packet capture or deep packet inspection.
- Editing secrets, notification channels, maintenance windows or server settings (listen, TLS, storage) from the UI. Targets, probe settings, alert thresholds and DNS probes are editable, see [Settings edited in the UI](#settings-edited-in-the-ui).
- A Prometheus `/metrics` endpoint (possible later, not planned). Data export and the printable ISP report are implemented, see [Export and ISP report](#export-and-isp-report).

## Key design decisions

| Area | Decision | Reason |
|---|---|---|
| Language | Go (current stable release, pinned in `go.mod`) | Stable, boring, single static binary, easy concurrency, great stdlib, cross-compiles to Windows/Linux/ARM |
| Storage | SQLite via `modernc.org/sqlite` (pure Go) | No CGO, so cross-compilation and releases stay trivial |
| UI | Embedded static HTML/JS via `go:embed`, vanilla JS, uPlot for line charts, canvas for the heatmap | No build toolchain required, fast with many points |
| Live updates | Server-Sent Events | Simpler than WebSockets, enough for one-way push |
| Config | Single YAML file, strict decoding | Easy to version and share; typos fail loudly |
| Default bind | `127.0.0.1` (binary); `0.0.0.0` in the Docker image | Safe default; remote access requires auth |
| Remote access | HTTP Basic auth (mandatory when not loopback) plus optional built-in TLS | Works standalone on a LAN and behind a reverse proxy |
| Hop probing | mtr-style: TTL-limited probes toward the destination, every round | Measures the path real traffic takes; detects path changes continuously |
| IP family | IPv4 implemented first; all types, schema, and interfaces are family-agnostic | IPv6 can be added without redesign |
| License | MIT | Short, permissive, common for Go tools |

### Dependencies

Stick to conventional, well-established libraries. Avoid heavy frameworks. Prefer the standard library where reasonable. Approved dependencies:

| Module | Purpose |
|---|---|
| `modernc.org/sqlite` | Pure-Go SQLite driver |
| `go.yaml.in/yaml/v3` | YAML config. Maintained continuation of the archived `gopkg.in/yaml.v3` (same API) |
| `golang.org/x/net` | `icmp`, `ipv4`, `ipv6` packages for the Linux prober |
| `golang.org/x/sys` | Windows `IcmpSendEcho2` and native service (`windows/svc`), Linux socket options |
| `github.com/oschwald/maxminddb-golang` | Optional: read a user-supplied GeoLite2 ASN database |
| uPlot (vendored JS, MIT) | Line charts in the UI |

Tests use the standard library only. Ask before adding anything else.

## How it works

### Target resolution

Each target's `host` is resolved once per discovery cycle (default 5 minutes). The resolved address is pinned for that cycle and used by every probe on the target: ICMP trace, TCP connect, and HTTP (via a custom dialer that keeps the original Host header and TLS SNI). This guarantees the hop view and the HTTP view measure the same destination, which matters for CDN and anycast hosts that return different addresses per lookup. The resolved IP is recorded on every path version and every sample.

If the resolved address changes, a new path version starts (see below). A per-probe `pin_ip: false` option lets HTTP probes resolve independently if the user explicitly wants that.

### Path tracing (ICMP, mtr-style)

Every round (default every 2 seconds, per target):

1. Send one ICMP Echo Request toward the **destination** for each TTL from 1 up to the current path length (initially `max_hops`). Probes within a round are sent with a small stagger (a few ms) rather than all at once.
2. Routers along the way reply "TTL exceeded", which reveals the hop address and its RTT; the destination replies with an Echo Reply.
3. Record, per TTL: responder address (or none), RTT, and status (reply, TTL exceeded, unreachable, timeout).
4. Stop at the first TTL where the destination answers. Trailing non-responding TTLs beyond the last responder are trimmed after a few rounds so we don't waste probes on `* * *` up to `max_hops`.

Because each round probes the whole path, path changes are detected continuously. The periodic "rediscovery" (default every 5 minutes) is a safety net: it re-resolves the target, re-probes up to `max_hops` to see if the path got longer, and resets trimming.

**Paris-style flow identity.** Keep the fields that ECMP load balancers hash on constant per target, so all probes for a target follow the same path. For ICMP Echo that means a constant identifier and a constant checksum: vary the sequence number for matching, and adjust two payload bytes to compensate so the checksum stays fixed. On Windows, `IcmpSendEcho2` does not expose the identifier/sequence, so Paris behavior there is best-effort (documented as a known limitation).

**Timeouts and late replies.** Each probe has a timeout (default 2 seconds, never longer than the round interval). A reply that arrives after its timeout counts as lost and is discarded.

**Load.** At 10 targets × ~15 hops every 2 seconds this is about 75 probes/second. Targets are started with random jitter so their rounds don't align.

### Path versions and hop identity

A **path version** is the ordered list of responders per TTL for a target and resolved IP. A new path version (new `paths` row) is created only when the observed path differs from the current one for N consecutive rounds (default 3), so a single odd reply doesn't create a path change. A TTL may legitimately have several responders within one path version (per-packet load balancing, routers answering from different interfaces). These are recorded as a responder set per TTL instead of starting new path versions.

Non-responding hops (`* * *`) are first-class. They render as a gap row and are excluded from latency aggregates instead of counting as zero.

### TCP connect probe

A privilege-free "tcping": time a TCP three-way handshake to `host:port` (default 443) on the pinned IP, then close. It serves two purposes:

- An end-to-end RTT and reachability signal for destinations that **drop ICMP Echo** (for example github.com). These are common.
- A cheap, high-frequency check alongside the slower HTTP probe.

**Destinations that don't answer ICMP.** If a target's destination never sends an Echo Reply during a discovery cycle, it is flagged `icmp_unresponsive`. For such targets the "final hop" metrics and the `final_hop_loss` rule use the TCP connect probe if one is configured, otherwise the last responding hop (with a UI note that end-to-end ICMP isn't available). The UI shows the destination row as "does not answer ping" rather than 100% loss.

### HTTP/HTTPS probes

Use `net/http/httptrace` to capture, per request: DNS lookup, TCP connect, TLS handshake, time to first byte, transfer (body read), and total time. Behavior:

- **A fresh connection on every probe** (keep-alives disabled), otherwise DNS/TCP/TLS read as zero after the first request.
- **Proxy environment variables are ignored by default** (`HTTP_PROXY`, `HTTPS_PROXY`), otherwise we would be measuring the proxy. Opt in with `use_env_proxy: true`.
- Method GET or HEAD. For GET, the body is read and discarded up to `max_body` (default 1 MiB) to measure transfer time.
- Optional: `expect_status` (one code or a list), `timeout`, `follow_redirects` (default false), custom `headers`, `user_agent` (default `pathwatch/<version>`), `insecure_skip_verify` for internal targets.
- **Header secrets:** `headers` values may reference environment variables as `${NAME}`, expanded when each request is built and never stored or returned expanded (the definition keeps the `${...}` text). Only names starting with `PATHWATCH_PROBE_` are readable; a reference to any other variable (`PATHWATCH_PASSWORD`, the SMTP password, ...) expands to the empty string, because targets can be created through the API and must not be able to exfiltrate other secrets. Write `$$` for a literal `$`. A literal value still works but is stored as written (in the YAML file or the database), so prefer `Authorization: Bearer ${PATHWATCH_PROBE_TOKEN}`.
- **Header handling elsewhere:** `GET /api/targets/{id}/config` replaces literal header values with `********` (values that are only `${...}` references, optionally after `Bearer`/`Basic`/`Token`, stay visible); a `PUT` that sends `********` keeps the stored value for the same probe (method + URL) and header name, and is rejected with "re-enter the header value" if the probe's URL or method changed. When following redirects, the configured headers are dropped from any hop whose scheme, host or port differs from the original URL. A password in the URL (`https://user:pass@host/`) is masked in the probe label, but still part of the probe key; prefer headers.
- When following redirects, phase timings are those of the first request; `total` covers the whole chain; the final URL and redirect count are recorded.
- The DNS phase uses the system resolver. When `pin_ip` is on (the default), the DNS phase reflects the per-cycle resolution. Note that the OS resolver cache usually makes it near-zero. For real resolver health, use the DNS probe.
- **TLS certificate expiry:** record the leaf certificate's `NotAfter` on every HTTPS probe; the `cert_expiry` alert rule warns ahead of expiry.

Default interval 30 seconds.

Interpretation:
- Slow DNS suggests resolver trouble.
- Slow TCP connect suggests network path trouble.
- Slow TLS or TTFB suggests server or application trouble.

### DNS probe

Query a specific resolver directly (UDP, with TCP fallback) for a name and record type, timing the response and recording the rcode. Uses a minimal stdlib-only DNS message encoder/decoder (A/AAAA queries only; no new dependency). Useful for detecting a slow or failing home router / Pi-hole / ISP resolver independently of any target. Default interval 30 seconds.

### The central insight

Intermediate routers often rate-limit or deprioritize ICMP replies to the monitor, so a middle hop can show heavy loss or latency spikes while real traffic passing through it is fine. Real problems show up at the final hop, at downstream hops, and in the TCP/HTTP probes. The UI and alerting should treat these accordingly.

**Hop classification (per evaluation window, default 1 minute).** For each hop k with loss above `loss_threshold` or latency above its baseline band:

- If **any** downstream signal is clean over the same window, hop k is classified **rate-limited** (annotate, never alert). Downstream signals are: some hop j > k, the destination's Echo Reply, or the target's TCP/HTTP probe. Clean means loss ≤ `loss_threshold` and latency within its band.
- If hop k **and every downstream signal** are degraded, the degradation is **real** and starts at hop k, the earliest degraded hop. This feeds the `path_degradation` rule and the UI marker "problem begins at hop k".

Rate-limited classifications are stored as state transitions (start/end), not per round, so a permanently lossy router produces one long annotation instead of a flood of events.

### Local outage detection

If hop 1 (the local gateway) or hop 2 stops responding, or all targets fail their end-to-end checks within the same window, pathwatch raises a single `local_connectivity` alert and suppresses per-target alerts that begin during it. Per-target alerts that would have fired are listed inside the local alert's details.

### Monitor gaps

Time during which pathwatch wasn't probing is **"no data"**, never loss. That covers the process stopped, the host or container suspended (common with NAS hibernation), or the scheduler stalling. Detection: each round records its timestamp. A gap greater than 3× the interval between consecutive rounds is stored as a gap. A wall clock that jumps backwards or forwards by more than the monotonic elapsed time is also treated as a gap. Gaps render as hatched/empty columns, are excluded from aggregates and baselines, and never trigger or resolve alerts.

### Platform layer

Define a small `Prober` interface: send a probe with a given TTL to a destination with given flow identifiers, and return the responder address, RTT, and status. Addresses use `netip.Addr` so IPv6 slots in. Build-tagged implementations:

- **Linux:** at startup, auto-detect the best available mode and log which one is used:
  1. Unprivileged ICMP datagram sockets (`SOCK_DGRAM`/`IPPROTO_ICMP`), with `IP_RECVERR` to receive TTL-exceeded errors, when `net.ipv4.ping_group_range` includes the process's group. Note: the kernel rewrites the ICMP identifier to the socket's port, so Paris identity uses one socket per target.
  2. Raw ICMP sockets, which require root or `CAP_NET_RAW` (`setcap cap_net_raw+ep`, `cap_add: [NET_RAW]` in Docker, or `AmbientCapabilities=CAP_NET_RAW` in systemd). Older NAS kernels (e.g. Synology DSM) commonly need this mode.
  A config option `icmp_mode: auto|dgram|raw` overrides detection.
- **Windows:** `IcmpSendEcho2` via `golang.org/x/sys/windows`. Allows setting TTL and returns the responding hop address without admin rights. Each in-flight probe runs in its own goroutine (the call blocks until reply or timeout).
- The HTTP, TCP connect, and DNS probers are pure stdlib and identical on every platform.

Later options: UDP and TCP-SYN traceroute modes for destinations or middleboxes that drop ICMP, and the IPv6 prober (ICMPv6 / `Icmp6SendEcho2`). The interface is designed so these slot in.

Use high-resolution timing: measure RTT with the monotonic clock (`time.Now()` / `time.Since`) around send/receive, and use kernel receive timestamps (`SO_TIMESTAMPNS`) on Linux where available. On Windows, be aware of timer resolution limits.

## Architecture

```
cmd/pathwatch/           main, subcommands, flag parsing, Windows service integration
internal/config/         YAML loading, strict validation, defaults/overrides resolution
internal/probe/          Prober interface, icmp (linux, windows), tcp, http, dns
internal/scheduler/      per-target goroutines, rounds, jitter, resolution pinning, path versioning
internal/analyze/        hop classification (rate-limited vs real), gap detection, local-outage detection
internal/store/          SQLite schema + migrations, batched writes, queries, aggregation, retention
internal/alert/          rule evaluation, baselines, state machine, silences, outbox, webhook and email senders
internal/enrich/         reverse DNS and ASN lookup with caching (off the probe hot path)
internal/web/            HTTP server, auth, TLS, JSON API, SSE, embedded static assets
web/static/              index.html, app.js, styles.css, vendored uPlot
```

**Concurrency model.** One goroutine per target runs its rounds, with bounded concurrency for in-flight probes. Probe results flow over a channel to:

- a single **writer goroutine** that batches inserts into SQLite (WAL mode, flush every ~1s or N rows);
- an **aggregator** that maintains in-memory 1-minute buckets per (target, TTL) and per HTTP/TCP/DNS probe and flushes completed buckets every minute;
- the **analyzer/alert engine**, which consumes per-minute aggregates.

Enrichment (rDNS, ASN) runs asynchronously with a cache so it never delays probing.

### CLI

```
pathwatch run [--config pathwatch.yaml]     # default when no subcommand is given
pathwatch check-config [--config ...]       # validate config and exit
pathwatch trace <host>                      # one-shot mtr-style trace to stdout, useful for testing the prober
pathwatch version
pathwatch service install|uninstall|start|stop   # Windows only, via golang.org/x/sys/windows/svc
```

### Logging and health

- Structured logging via `log/slog` (text or JSON, configurable level). Optional `log_file` with size-based rotation for the Windows service, where there is no console.
- Never log secrets (passwords, webhook URLs with tokens, auth headers).
- `GET /healthz` (unauthenticated, returns no data beyond status): 200 when the scheduler and writer are alive and the last round is recent.

## Data model

Adjust as needed during implementation. All timestamps are Unix microseconds UTC (`INTEGER`). The schema is created and evolved through embedded, numbered migrations tracked in a `schema_version` table, from the first release.

```sql
-- config `name` is the stable identity; removed targets are kept with active = 0
targets(id, name UNIQUE, host, active, created_at, updated_at)

-- a path version per target; new row when the path or resolved IP changes (debounced)
paths(id, target_id, resolved_ip, started_at, ended_at)
-- responder set per TTL; multiple rows per (path_id, ttl) allowed for load-balanced hops
path_hops(path_id, ttl, address, share)           -- share = fraction of replies from this responder

-- enrichment keyed by address, shared across paths; private/CGNAT ranges are not looked up
ip_info(address PRIMARY KEY, hostname, asn, as_name, updated_at)

-- raw ICMP: one row per (target, round); per-TTL results packed in a compact blob
-- blob = for each ttl: status(1B) | rtt_us(varint) | responder index into path_hops
icmp_rounds(target_id, ts, path_id, hop_count, results BLOB, PRIMARY KEY(target_id, ts)) WITHOUT ROWID

-- raw probe samples
http_samples(probe_id, ts, resolved_ip, status, dns_us, connect_us, tls_us, ttfb_us, transfer_us,
             total_us, redirects, cert_not_after, error, PRIMARY KEY(probe_id, ts)) WITHOUT ROWID
tcp_samples(probe_id, ts, resolved_ip, connect_us, error, PRIMARY KEY(probe_id, ts)) WITHOUT ROWID
dns_samples(probe_id, ts, rcode, rtt_us, error, PRIMARY KEY(probe_id, ts)) WITHOUT ROWID
probes(id, target_id, type, key)                   -- key = stable id derived from the probe config

-- monitor gaps (process stopped, host suspended, clock jump)
gaps(target_id, started_at, ended_at)

-- rollups: 1-minute (retained ~90 days) and 1-hour (retained long term), same shape
-- hist = fixed log-scale latency histogram (compact blob) so percentiles stay correct when merged
icmp_rollup_1m(target_id, ttl, bucket, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist)
probe_rollup_1m(probe_id, bucket, n, errors, phase_avgs..., total_min, total_avg, total_max, hist)
-- icmp_rollup_1h / probe_rollup_1h identical

-- annotations: rate-limited hops, route changes, icmp_unresponsive flags (state transitions only)
events(id, target_id, kind, ttl, started_at, ended_at, details_json)

alerts(id, target_id, rule, state, started_at, ended_at, peak_value, baseline, details_json)
-- persistent outbox: survives restarts, retried with backoff until delivered or expired
outbox(id, alert_id, channel, payload, created_at, attempts, next_attempt_at, delivered_at, last_error)
silences(id, target_id NULL, rule NULL, starts_at, ends_at, reason, created_by)
```

**Storage budget.** With one row per round, 10 targets at a 2-second interval produce ~430k ICMP rows/day, roughly 100 to 200 MB per week of raw data. One row per hop sample would be about 15× more rows and several GB per week. Use `PRAGMA auto_vacuum = INCREMENTAL` and run incremental vacuum after retention deletes.

**Aggregation and retention.**
- 1-minute rollups are produced **continuously** by the in-memory aggregator and flushed each minute, so the dashboard always has current data at every range.
- 1-hour rollups are built from 1-minute rollups as each hour completes.
- Percentiles (p50, p95, p99) are computed from the merged histograms, never by averaging percentiles.
- Jitter: mean absolute difference of consecutive RTTs (RFC 3550 style), computed on successful replies only. Lost probes count toward loss and never toward latency.
- On startup, rollups are backfilled from raw data for any buckets missed while the process was down.
- A retention job (hourly) deletes expired raw and rollup data. Retention periods are configurable.

**Database location.** The SQLite file must live on a local filesystem. WAL mode does not work reliably on network filesystems (NFS/SMB). On a NAS, point it at a local volume, not a share mounted from elsewhere.

## Web UI

Pages:

### Overview (landing page)

One row or card per target: status (OK / degraded / alerting / silenced / no data), current end-to-end latency and loss, HTTP success rate, and a sparkline of end-to-end latency for the selected range. Also: active alert count, local connectivity status, and DNS probe results. Clicking a target opens its page.

### Target page

Target selector at the top and a time-range selector: **1h, 6h, 24h, 7d, 30d, 90d, and custom** (date/time picker). **Drag-to-zoom** on any chart narrows the range for all panels together, and a "reset zoom" control restores it. The resolution tier is chosen automatically: raw data for ranges ≤ 6h, 1-minute rollups up to 7d, and 1-hour rollups beyond that.

1. **Summary cards:** end-to-end latency (median and p95), end-to-end loss (destination, or TCP probe if ICMP is unavailable), HTTP total latency and success rate, certificate expiry, active alert count.
2. **Path timeline:** one row per TTL, one column per time bucket, cell shade by latency intensity, red for lost probes, hatched for monitor gaps. On the left: hop number, the most common responder in the range (hostname if known, otherwise the address), and average latency. A hop with multiple responders shows a small "+N" badge. Rate-limited hops are visually de-emphasized and labeled "ICMP rate-limited". Markers above the timeline show route changes, alerts, and silences. Hover shows exact values, the responder at that moment, and the classification. Render with canvas (not DOM nodes per cell) so long ranges stay fast.
3. **HTTP phases chart:** stacked DNS, TCP, TLS, TTFB, transfer per sample or bucket, aligned to the same time axis as the path timeline. TCP connect probe latency is overlaid as a line when configured.
4. **Alerts feed:** recent alerts with which channels fired and delivery status (delivered, queued, retrying), plus suppressed events (such as rate-limited hops and alerts suppressed by a silence or a local outage) shown as logged, not sent. Silences can be created and ended from here.

Keep the visual style flat and clean, with dark mode support via `prefers-color-scheme`. Use a sequential single-hue scale for latency and red for loss. The latency scale is shared across all rows of a view: 0 to the view's p99, adjustable.

All times are stored in UTC and displayed in the browser's local timezone.

### Export and ISP report

The target page has **Export CSV**, **Export JSON** and **Report** controls that use the time range on screen (a Hops/Probes selector chooses what is exported).

- **Export** (`GET /api/targets/{id}/export`): rollup rows as a file download. Hops: per bucket and TTL, the hop address, hostname and ASN where known, probes sent and lost, loss %, and RTT min/avg/max/jitter/p95. Probes: per HTTP/TCP probe and bucket, the phase averages, total min/avg/max/p95 and the error count. The resolution follows the range like the history endpoints (1-minute buckets up to 7 days, 1-hour beyond; `res=1m|1h` overrides). The range is bounded and a request that would exceed 250,000 rows is refused with 400. The file is streamed. Text cells that a spreadsheet could read as a formula (leading `=`, `+`, `-`, `@`, tab or CR) get a leading single quote in CSV, because reverse-DNS hostnames are attacker-influenced. The control is a plain same-origin link, so it needs no script and works under the CSP. The hop identity is that of the path version current at the end of the range.
- **Report** (`GET /api/targets/{id}/report`, page `#/target/{id}/report?from=&to=`): a page meant to be printed or saved as PDF to hand to an ISP. It shows the summary (destination availability and loss, latency average and p95, jitter, MOS, HTTP/TCP success), the incidents of the range (alerts and degradation events with start, duration, kind and severity), for each incident the first hop where loss or latency degradation starts (found with the same classifier as the live analysis, with address, hostname and AS) and the HTTP/TCP probe impact during it, monitor gaps (shown as "no data", never as loss) and path changes. `@media print` hides the navigation and controls and forces light colours.

**JSON API** (internal, used by the UI): targets and status, current path, time-bucketed samples for a range (the server picks the tier), events, alerts, silences (create/end), plus an SSE endpoint that pushes each completed round and probe result for live updates.

## Access and security

- **Bind address.** The binary binds to `127.0.0.1:8080` by default. The Docker image sets `PATHWATCH_LISTEN=0.0.0.0:8095`, so the web UI is reachable from the whole network by default.
- **Authentication.** If `listen` is not a loopback address, Basic auth is always on. When no password is configured (`auth.basic_password_env` / `PATHWATCH_PASSWORD`), pathwatch generates one on first start, stores it in `/data/.pathwatch-password` (mode 0600; next to the database) and logs it once. Anyone with access to the container logs or the data folder can read it, so setting `PATHWATCH_PASSWORD` explicitly is recommended. On a loopback bind with no password configured, authentication is off and a log line says so. `/healthz` is exempt from auth.
- **Weak passwords and brute force.** A startup warning is logged when `PATHWATCH_PASSWORD` is shorter than 12 characters. Failed Basic-auth attempts are rate-limited per client IP (IPv6 per /64; `X-Forwarded-For` is ignored): after three wrong guesses the client gets `429` with a `Retry-After` header, without its credentials being checked, for a backoff that starts at 250 ms and doubles per further failure up to 5 minutes. A successful login resets it; requests without credentials are not counted. Failures are logged at warn level with the message `authentication failed` and the remote address (at most once per client per minute, with the count since the last line; suitable for fail2ban). Behind a reverse proxy the client IP is the proxy's, so rate-limit at the proxy as well.
- **Clear-text credentials.** Without TLS, Basic auth credentials cross the network in clear text. Use plain HTTP only on a trusted LAN and never forward the port from the internet. For anything else use a VPN, an HTTPS reverse proxy (Caddy, Traefik, Synology's built-in reverse proxy) or built-in TLS (`tls.cert_file` and `tls.key_file`). The README "Security" section and docs/SYNOLOGY.md ("Securing access") repeat this for users. The image's healthcheck is plain HTTP (`GET /healthz` via `deploy/healthcheck.sh`), so with built-in TLS it fails: override `healthcheck:` in the compose file (for example a `wget --no-check-certificate` call to `https://127.0.0.1:8095/healthz`) or terminate TLS in a reverse proxy instead.
- **DNS-rebinding protection.** While authentication is off, requests whose `Host` header is not `localhost`, an address in `127.0.0.0/8`, `::1`, or the host of `public_url` are rejected with `421 Misdirected Request`. `X-Forwarded-Host` is deliberately not trusted for this check. A local reverse proxy in front of an auth-less loopback instance therefore needs its public hostname in `public_url` (or, better, a password, which turns authentication on and this check off).
- **Security headers.** Every response carries `Content-Security-Policy` (with `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`, so the UI cannot be framed. `Strict-Transport-Security` is added only when built-in TLS is enabled.
- **CSRF model.** The API is same-origin only. Every request with a method other than GET, HEAD or OPTIONS passes the `sameOrigin` check: it is accepted when `Sec-Fetch-Site` is `same-origin` or `none` and refused when it is `cross-site` or `same-site`. When the header is absent (older browsers) the `Origin` header, if present, must match `Host`, the first `X-Forwarded-Host` value, or the host of `public_url`; requests without an `Origin` (curl, scripts) pass. Endpoints that take a body (targets, settings, silences) also require `Content-Type: application/json`, which blocks simple cross-site form posts; body-less ones (DELETE, pause/resume) rely on `sameOrigin` alone. Reverse-proxy users should set `public_url` and forward `X-Forwarded-Host`, since both feed this check.
- Passwords are compared in constant time.
- `public_url` (for example `https://nas.local:8080`) builds deep links in alerts. Without it, alerts omit the link.
- Never log secrets.

## Alerting

Principle: the end-to-end probes (HTTP, TCP, destination ICMP) are the arbiter. ICMP loss or latency on intermediate hops never pages on its own.

### Rules

Rules are defined globally and apply to every target that has the probes a rule needs (a rule needing an HTTP probe is skipped for targets without one). Targets can disable rules or override parameters (see the config example).

| Rule type | Fires when |
|---|---|
| `http_failure` | Error or unexpected status for N consecutive HTTP probes |
| `http_latency` | Total (or TTFB) above `multiplier` × baseline **and** above baseline + `min_delta`, sustained for `sustain` |
| `final_hop_loss` | End-to-end loss (destination ICMP, or TCP probe for ICMP-unresponsive targets) above `threshold_pct` over `window` (the window must be fully covered by data; loss at an intermediate hop, which is what the end-to-end figure falls back to when neither the destination nor a TCP probe answers, never alerts) |
| `path_degradation` | The hop classifier marks degradation as real (a hop and all downstream signals degraded) for `sustain` |
| `tcp_failure` | N consecutive TCP connect failures |
| `dns_failure` / `dns_latency` | DNS probe errors / SERVFAIL for N consecutive probes, or latency anomaly |
| `cert_expiry` | Certificate expires within `warn_before` (default 14d); fires once per certificate |
| `route_change` | Optional, off by default: notify when a new path version starts. A one-shot alert: it is recorded as resolved immediately and sends a single notification (state `event`) |
| `local_connectivity` | Built in; see [Local outage detection](#local-outage-detection) |

### Baselines and anomaly detection

Rolling median plus MAD per metric, computed from 1-minute rollups over `baseline_window` (default 24h). No ML.

- **Cold start:** latency-anomaly rules stay inactive until the baseline holds at least `min_baseline` of data (default 2h). The UI shows "learning baseline".
- **Frozen while firing:** the baseline is frozen while an alert on that metric is firing, and periods spent in an alert are excluded from future baselines. Otherwise a long incident becomes the new normal and resolves itself.
- **Absolute floor:** a latency alert requires both the multiplier and `min_delta` (default 50ms), so 3× a 5ms baseline doesn't page. It also has to clear a noise band of 4 robust standard deviations (1.4826 × MAD) above the median, so a naturally jittery metric needs a bigger excursion.
- The baseline is a median over per-minute averages, cached and recomputed every five minutes (not every minute), and it leaves out the most recent `sustain` + 1 minute so the excursion being judged cannot feed it.
- Monitor gaps are excluded from baselines.

### Noise control

- A condition must hold for its window/sustain before firing.
- Hysteresis: clear at a lower threshold than the trigger (default 70% of the trigger threshold) and only after holding for the same window. For latency rules whose 70% would not even be above the baseline (a small multiplier), the clear level is the midpoint between baseline and trigger. For `final_hop_loss` the trailing `window` of loss is itself the hold: it fires when the loss over the last full window exceeds the threshold and clears when the loss over the last full window is below the clear level. Consecutive-failure rules (`http_failure`, `tcp_failure`, `dns_failure`) clear after the same number of consecutive successes. The recorded end time of an alert is when the problem stopped (the start of the clear hold), not when the hold finished.
- Per (target, rule) cooldown after a resolve before the same alert can fire again.
- A "resolved" notification includes the duration. Cooldown never suppresses resolved notifications.
- Alert state persists in SQLite, so a restart neither re-fires nor loses active alerts (cooldowns, and the "once per certificate" and "once per route change" memory, are restored too).
- Probe-based rules (consecutive failures, `cert_expiry`) are evaluated when the minute a probe result belongs to is analysed, so the local-outage verdict for that time is known first. Alerts for them therefore appear up to about two minutes after the condition begins.

### Silences and maintenance windows

- **Silences** are created in the UI or config, scoped to a target, a rule (name or type), or everything, with a start and end time. Silenced alerts are still evaluated and logged ("suppressed by silence") but not sent. A suppressed alert (silence, maintenance window or cooldown) whose condition is still true when the suppression ends becomes a firing alert and is sent then, with its real start time; one suppressed by a local outage stays suppressed. A firing alert is never affected by a silence created later, and its "resolved" notification is always sent.
- **Maintenance windows** are recurring silences defined in config (for example, the ISP's nightly maintenance or the NAS's scheduled reboot), with a cron-like weekday + time range.

### Delivery: outbox and retry

Every notification is written to the `outbox` table first, then delivered by a sender goroutine with exponential backoff (30s, 1m, 2m, 4m, 8m, then every 15m, up to `max_age`, default 24h). Statuses: `queued`, `retrying`, `delivered`, `failed` (cannot ever succeed, e.g. a broken `body_template`) and `expired`. A "resolved" notification is never sent before the "firing" one of the same alert and channel. Notifications about an outage of your own connection are therefore delivered when it comes back, and include the actual start and end times. Delivery status appears in the alerts feed.

### Heartbeat (dead-man's switch)

Optional: `heartbeat.url` gets a GET every `heartbeat.interval` while pathwatch is healthy. Point it at a service such as healthchecks.io or Uptime Kuma, which alerts if the heartbeats stop. Off by default. No URL is built in.

### Channels

- **Webhook:** POST JSON containing target, rule, state (firing or resolved; `event` for one-shot `route_change` alerts), current value, baseline, timestamps (RFC 3339 and Unix ms), and a deep link (if `public_url` is set). The URL comes from `url_env` and, like header values, is never logged; header values may use `${ENV_VAR}`. Requests time out after 10s and a non-2xx response counts as a failure. Presets for `discord`, `slack` (and Slack-compatible), `ntfy`, and `generic` (raw JSON, for n8n or Home Assistant). A custom body is possible via a Go `text/template`. A custom body for Discord must use `{{json .Message}}` and include `"allowed_mentions": {"parse": []}`, because alert text can contain text chosen by the probed server and would otherwise be able to ping `@everyone`. Optional custom headers (values may reference environment variables).

  **Custom body (`body_template`).** The body is a Go `text/template` rendered with these fields: `AlertID`, `Title` (for example `FIRING cloudflare: http-slow`), `State` (`firing`, `resolved` or `event`), `Target`, `TargetID` (0 when the alert has no target), `Rule`, `RuleType`, `Message`, `Value`, `PeakValue`, `Baseline` (numbers), `Unit`, `ValueText` (for example `412 ms`), `BaselineText`, `StartedAt` and `EndedAt` (RFC 3339 UTC; `EndedAt` is empty while firing), `StartedAtMS` and `EndedAtMS` (Unix ms; 0 while firing), `Duration` (for example `5m3s`), `DurationSeconds`, `Link` (empty without `public_url`) and `Details` (a JSON string). Helper functions: `json` (JSON-encodes any value, including the surrounding quotes), `upper`, `lower` and `trim`.

  `text/template` does no escaping. Target and rule names are user-entered, and `Message` can contain the last probe error (up to 160 characters), which may include text derived from the remote side such as a TLS certificate host name. A value containing `"`, a backslash or a newline inside a hand-quoted JSON string yields invalid JSON, or lets the value inject extra JSON fields. **When building JSON, wrap every string field in `{{json ...}}` and do not add your own quotes around it:**

  ```yaml
  body_template: '{"text": {{json .Title}}, "target": {{json .Target}}, "rule": {{json .Rule}}, "state": {{json .State}}, "message": {{json .Message}}, "link": {{json .Link}}, "value": {{.Value}}}'
  ```

  Numeric fields (`Value`, `PeakValue`, `Baseline`, `AlertID`, ...) may be inserted bare.
- **Email:** SMTP with host, port, and TLS mode `starttls` (587), `tls` (implicit TLS, 465), or `none`. Username and password come from environment variables. One message per alert event, not per probe.
- **Routing:** each rule may list the channels it notifies (default: all). For example, route changes could go to the webhook only.

## Config example

```yaml
listen: 127.0.0.1:8080
public_url: https://nas.local:8080   # optional; used for deep links in alerts

auth:
  # required if listen is not loopback
  basic_user: admin
  basic_password_env: PATHWATCH_PASSWORD

tls:                                  # optional built-in HTTPS
  cert_file: /config/tls/cert.pem
  key_file: /config/tls/key.pem

log:
  level: info                         # debug | info | warn | error
  format: text                        # text | json
  file: ""                            # optional; rotated by size

storage:
  path: ./pathwatch.db                # must be on a local filesystem
  raw_retention: 7d
  rollup_1m_retention: 90d
  rollup_1h_retention: 0              # keep forever

probing:
  icmp_mode: auto                     # auto | dgram | raw (Linux)

defaults:                             # inherited by every target/probe; overridable at either level
  icmp_interval: 2s
  icmp_timeout: 2s
  tcp_interval: 10s
  http_interval: 30s
  dns_interval: 30s
  path_rediscovery: 5m
  max_hops: 30
  retries: 0                          # retries of a failed HTTP/TCP/DNS probe (0-10); ICMP never retries

status:                               # when a target shows as "degraded"
  degraded_loss_pct: 5                # end-to-end loss above this over the last 5 minutes
  degraded_http_success_pct: 95       # HTTP success below this over the last 5 minutes

targets:
  - name: cloudflare
    host: cloudflare.com
    probes:
      - type: icmp-trace
      - type: http
        url: https://cloudflare.com/
        method: HEAD
        expect_status: [200, 301]
        timeout: 10s
  - name: github                      # does not answer ping; TCP probe provides end-to-end signal
    host: github.com
    probes:
      - type: icmp-trace
      - type: tcp
        port: 443
        retries: 2                    # per-probe override (also settable per target)
      - type: http
        url: https://github.com/
        expect_status: 200
        interval: 60s                 # per-probe override
  - name: dns-google
    host: 8.8.8.8
    icmp_interval: 5s                 # per-target override
    probes:
      - type: icmp-trace
    alerts:
      disable: [route_change]
      override:
        end-loss: { threshold_pct: 10 }

dns_probes:
  - name: home-resolver
    server: 192.168.1.1:53
    query: example.com
    record: A

alerts:
  rules:
    - name: http-down
      type: http_failure
      consecutive: 3
    - name: http-slow
      type: http_latency
      metric: total                   # total | ttfb
      baseline_window: 24h
      min_baseline: 2h
      multiplier: 3
      min_delta: 50ms
      sustain: 5m
    - name: end-loss
      type: final_hop_loss
      threshold_pct: 5
      window: 5m
    - name: path-degraded
      type: path_degradation
      sustain: 5m
    - name: tcp-down
      type: tcp_failure
      consecutive: 3
    - name: resolver-down
      type: dns_failure
      consecutive: 3
    - name: cert
      type: cert_expiry
      warn_before: 14d
    - name: route
      type: route_change
      enabled: false
      notify: [webhook]               # per-rule channel routing
  cooldown: 30m
  clear_ratio: 0.7                    # hysteresis
  maintenance_windows:
    - name: isp-nightly
      days: [mon, tue, wed, thu, fri, sat, sun]
      start: "03:00"
      end: "04:00"
      timezone: America/New_York
  heartbeat:
    url: ""                           # e.g. a healthchecks.io ping URL; empty = off
    interval: 5m
  outbox:
    max_age: 24h
  notify:
    webhook:
      url_env: PATHWATCH_WEBHOOK_URL  # webhook URLs often embed tokens
      preset: discord                 # discord | slack | ntfy | generic
      headers: {}
      # body_template: '{"text": {{json .Title}}, "target": {{json .Target}}}'   # always {{json ...}} for strings
    email:
      smtp_host: smtp.example.com
      smtp_port: 587
      tls: starttls                   # starttls | tls | none
      username_env: PATHWATCH_SMTP_USER
      password_env: PATHWATCH_SMTP_PASS
      from: pathwatch@example.com
      to: [me@example.com]
```

Config rules:
- **Strict decoding:** unknown keys are errors.
- Durations accept Go syntax (`90s`, `5m`, `168h`) plus a `d` suffix for days.
- Target `name` is the stable identity in the database. Renaming a target starts a new history, so the README says so. Changing `host` starts a new path version.
- Targets removed from config keep their data and are marked inactive (hidden by default, shown with a toggle).
- Config changes take effect on restart (or `SIGHUP` on Linux, which reloads targets, rules, and channels). Full hot reload is a later item.
- Secrets are read from environment variables, never inline (probe header values can opt in with `${PATHWATCH_PROBE_*}`; see HTTP/HTTPS probes).
- New data directories are created `0700`, and the database and starter config `0600`. Existing files keep their mode; a startup warning is logged when the config or database is readable by group or others.

## Distribution

- **Docker (primary):** multi-arch image (linux/amd64, linux/arm64) published to GHCR on every tag. Alpine base with CA certificates and tzdata (a shell is kept for debugging). The container runs as root: raw ICMP sockets work reliably as root + `NET_RAW` on Synology kernels, where unprivileged datagram ICMP (`ping_group_range`) is often not enabled. The binary carries no file capability. The shipped compose files confine the root process: `cap_drop: [ALL]` plus `cap_add: [NET_RAW]`, `no-new-privileges`, `read_only: true` and a `/tmp` tmpfs, because everything pathwatch writes (config, database, generated password, optional log file) lives under `/data`. Without `DAC_OVERRIDE`, `/data` must be owned by root or be world-writable (on Synology run `chown root:root` on the folder, or add `DAC_OVERRIDE`). A `log.file` outside `/data` cannot be opened under `read_only`; pathwatch then logs to stderr only. A non-root profile needs a file capability on the binary (or datagram ICMP) and does not combine safely with `no-new-privileges` on every runtime; it is not the default. Compose example:

  ```yaml
  services:
    pathwatch:
      image: ghcr.io/i-press-buttons/pathwatch:latest
      network_mode: host           # accurate paths; avoids the Docker NAT hop
      cap_drop: [ALL]
      cap_add: [NET_RAW]
      security_opt: ["no-new-privileges:true"]
      read_only: true
      tmpfs: [/tmp]
      environment:
        PATHWATCH_PASSWORD: ${PATHWATCH_PASSWORD}
      volumes:
        - ./data:/data              # config, SQLite DB, password: must be local disk, not NFS/SMB
      restart: unless-stopped
  ```

  Document NAS specifics: Synology/QNAP container managers, host networking, and checking which ICMP mode was detected in the logs.
- **Binaries:** GoReleaser and GitHub Actions build Windows (amd64), Linux (amd64, arm64, armv7) on every tag.
- **Linux:** sample systemd unit with `AmbientCapabilities=CAP_NET_RAW`, `DynamicUser=yes`, and a `StateDirectory`.
- **Windows:** native service via `pathwatch service install` (`golang.org/x/sys/windows/svc`), logging to a file.
- **License:** MIT.
- **Privacy:** no telemetry and no calls to third-party APIs by default. Reverse DNS for hop addresses goes to the system resolver (can be disabled). ASN enrichment uses a user-supplied local GeoLite2 ASN database, or DNS-based lookup (Team Cymru), which is **off by default**. Private and CGNAT addresses are never looked up. The heartbeat is off unless configured.
- **Security defaults:** bind to loopback, require auth if bound elsewhere, never log secrets, secrets only from environment variables.

## v1 deployment and UX additions (Synology + Portainer)

These additions take precedence over earlier sections where they conflict.

- **One volume, zero-config first run.** In Docker everything lives under `/data`: `/data/pathwatch.yaml` and `/data/pathwatch.db`. If the config file is missing, pathwatch writes a commented starter config with a few example targets (cloudflare.com with HTTP, 1.1.1.1, 8.8.8.8) and starts.
- **Environment overrides** (handy in Portainer): `PATHWATCH_CONFIG` (default `/data/pathwatch.yaml` in the image), `PATHWATCH_DB` (overrides `storage.path`), `PATHWATCH_LISTEN` (overrides `listen`; image default `0.0.0.0:8095`), `PATHWATCH_PASSWORD` (Basic auth password, user defaults to `admin`), `PATHWATCH_USER`, `TZ`.
- **Generated password.** If the bind is not loopback and no password is configured, pathwatch generates a random password on first start, stores it in `/data/.pathwatch-password`, and logs it prominently. This replaces "startup fails". Auth is still always on when the bind is not loopback.
- **UI-managed targets.** Targets can be added, paused, and removed in the UI (stored in the database, `source: ui`) in addition to config-file targets (`source: config`, read-only in the UI apart from pause). This revises the "UI is read-only" non-goal.
- **Path views:** a hop grid (hop, IP, hostname, sent/lost, loss %, min/avg/max/cur/p95, jitter, classification, inline latency bar), the path timeline heatmap, and a latency/loss graph for the selected hop (default: destination). Clicking a hop row selects it. Also live updates via SSE.
- **MOS score** per target from latency, jitter, and loss (simplified ITU-T G.107 E-model), shown in summary cards and the overview.
- **Themes.** Several built-in themes selectable in the UI and remembered per browser: Auto (follows `prefers-color-scheme`), Light, Dark, Midnight, Nord, Solarized Light, Solarized Dark, High Contrast, and Classic (green/yellow/red latency scale). Each theme defines its UI colors and its latency/loss color scale.
- **Image:** `ghcr.io/i-press-buttons/pathwatch`, multi-arch (linux/amd64, linux/arm64). Tags: `latest` from the default branch, `edge` from the default branch too (branch and pull request builds are not published), and semver tags on releases. Runs as root inside the container (simplest reliable raw-socket access on Synology kernels), with `network_mode: host` and `cap_add: [NET_RAW]`.
- **API contract:** see [API.md](API.md).

### Settings edited in the UI

Everything about what is monitored and when it alerts has a UI control:

- **Targets** (Overview → Add target / Edit, or the target page): name, host, hop trace on/off with interval, timeout, max hops and rediscovery interval, any number of HTTP probes (URL, method, expected status, interval, timeout, retries, redirects, TLS verification) and TCP probes (port, interval, timeout, retries), and per-target alert settings (turn rules off, override their thresholds).
- **Settings page:** probe defaults (every interval and timeout, max hops, rediscovery, retries), status thresholds (when a target turns "degraded"), alert rules (add, remove, enable, thresholds, channel routing, cooldown, clear ratio), and DNS probes.

Storage and precedence: UI edits are stored in the database (`settings` table and `targets.spec`) and layered over the config file. An edited section (defaults, status, alerts, DNS probes) replaces the file's section; an edited config-file target is replaced by its edited definition (matched by name). Each can be reverted to the file in the UI. Changes apply immediately without a restart, and SIGHUP reloads keep the UI edits. If stored settings no longer fit a changed config file (for example a rule they refer to was removed), pathwatch logs it and falls back to the file's sections rather than failing to start.

**Limits.** At most 200 targets (config-file and UI-created together), 16 probes per target and 50 DNS probes. They apply to the config file (more is a validation error) and to the API (400 with the message), so a client with write access cannot make the instance run an unbounded number of probes. The 200-target total is checked when a target is created; a database that already holds more (from an older version) still starts, keeps its targets and only refuses new ones. A stored UI target over the probe cap is logged and not run until it is edited down; stored DNS probe lists over the cap fall back to the file's, as for any other stored setting that no longer fits.

**Hosts.** A target host is a hostname (fully qualified, with or without a trailing dot, or a short name completed by the system resolver), an IPv4 address or an IPv6 address (brackets accepted). Hosts are normalized; URLs and `host:port` are rejected with a message that says what to change. The UI shows what kind of host was entered and can resolve it before saving. Hostnames are re-resolved every `path_rediscovery` and the IPv4 address is preferred. Hop tracing is IPv4-only (see Later); HTTP and TCP probes work over IPv6.

**Retries.** `retries` (0–10, default 0) applies to HTTP, TCP and DNS probes: a failed attempt is retried after 250 ms, as long as another attempt can finish before the probe is next due, and only the final outcome is recorded (a failure notes the number of attempts). Retries trade sensitivity for fewer one-off failures; the consecutive-failure alert rules are the other knob. ICMP hop probes never retry: an unanswered probe is the loss being measured.

## Known pitfalls

- Router ICMP rate limiting and deprioritization (see the central insight above).
- Destinations that never answer ICMP Echo (handled by `icmp_unresponsive` + TCP probe).
- CDN/anycast hosts resolving to different IPs (handled by per-cycle IP pinning).
- Route changes and ECMP: track hop identity per path version with responder sets; debounce changes.
- Non-responding hops (`* * *`) must render gracefully and not break aggregates.
- Monitor downtime, host suspend, and clock jumps must appear as gaps, not loss.
- HTTP keep-alive and proxy environment variables silently corrupt phase timings.
- Percentiles cannot be averaged: use mergeable histograms.
- Windows timer resolution can add noise, and Paris behavior is best-effort on Windows.
- Reverse DNS and ASN lookups must be cached and asynchronous.
- SQLite: batch inserts, WAL mode, local filesystem only, incremental vacuum after retention deletes.
- Containers can alter apparent paths, so prefer host networking for tracing.
- Old NAS kernels may lack unprivileged ICMP sockets; use raw sockets with `NET_RAW`.

## Related tools (for reference and a quick niche check)

mtr and WinMTR (live per-hop, no history), Trippy (Rust TUI traceroute), Smokeping (long-term latency and jitter, no per-hop timeline), Prometheus blackbox_exporter with Grafana (history and alerting, no hop analysis), and commercial path-analysis tools. This project's niche is a self-hosted, always-on, per-hop timeline with HTTP phase correlation in a single easy-to-install binary with a built-in web UI.

## Milestones

1. **Skeleton:** config loading (strict, defaults/overrides, validation), SQLite schema with migrations, Linux prober (dgram/raw auto-detect), mtr-style rounds with Paris flow identity, target resolution pinning, path versioning with debounce, raw round rows stored, `check-config` and `trace` subcommands.
2. **Endpoint probes:** HTTP/HTTPS with phase timing (fresh connections, pinned IP, cert expiry), TCP connect probe, DNS probe; `icmp_unresponsive` detection.
3. **Aggregation:** continuous 1-minute aggregation with histograms, 1-hour rollups, startup backfill, retention job, gap detection.
4. **Docker:** Dockerfile, compose example, multi-arch GHCR build in GitHub Actions. Deployed to the NAS for real-world soak testing from here on.
5. **Web UI:** overview page, target page (summary cards, canvas path timeline, HTTP phases chart), ranges 1h to 90d plus custom, drag-to-zoom, SSE live updates, Basic auth, optional TLS.
6. **Alerting:** hop classifier, local-outage detection, rule engine with baselines (cold start, freeze, `min_delta`), hysteresis and cooldown, persistent outbox with retry, webhook presets and email, silences and maintenance windows, heartbeat, alerts feed in the UI.
7. **Packaging and Windows:** Windows prober (`IcmpSendEcho2`) tested on Windows 10/11, native Windows service, systemd unit, GoReleaser binaries, README with screenshots.
8. **Later:** IPv6 prober, UDP and TCP-SYN trace modes, ASN and rDNS enrichment polish, full config hot reload, possibly export/ISP report and Prometheus metrics.

## Instructions for the coding agent

- Start with milestone 1 and keep each milestone working and committed before moving on.
- Write tests for the pure logic: config validation and override resolution, Paris checksum compensation, path versioning and debounce, hop classification, gap detection, aggregation and histogram merging, rollups, baselines and the alert state machine, outbox retry scheduling, and the DNS message codec. Probe code that needs raw sockets is tested behind a fake `Prober` that replays scripted paths (including load-balanced hops, rate-limited hops, and unresponsive destinations).
- Keep dependencies minimal and mainstream, limited to the approved list above. No CGO.
- Ask before adding any dependency not listed here.
- Keep the README current as features land.

## Changelog vs. original spec

Resolved ambiguities and holes:
- Hop probing is now explicitly **mtr-style** (TTL-limited probes to the destination every round) instead of pinging hop addresses directly. Rediscovery becomes a safety net.
- **Destinations that drop ICMP Echo** (e.g. github.com in the original example) are detected. A new privilege-free **TCP connect probe** provides the end-to-end signal.
- **Per-cycle IP pinning** keeps ICMP and HTTP measuring the same address on CDN/anycast hosts.
- "Clean downstream" is defined as a concrete **hop classification** algorithm that covers latency as well as loss.
- **Persistent outbox** so alerts about your own outage are delivered after recovery.
- **Local outage detection** groups simultaneous failures into one alert.
- **Monitor gaps** (downtime, suspend, clock jumps) are "no data", never loss.
- Alerting gains cold-start handling, baseline freezing, `min_delta` floor, implicit-TLS email, webhook presets, per-rule routing.
- HTTP probe: fresh connection per probe, proxy env ignored, transfer phase, redirect semantics.
- Storage: one raw row per round (packed), continuous 1-minute aggregation (not nightly), mergeable histograms for correct percentiles, migrations, incremental vacuum, local-disk requirement.
- Path versions with debounce and responder sets for load-balanced hops; enrichment moved to an `ip_info` table.
- Config: strict decoding, overrides, per-target rule settings, `public_url`, `d` durations, secrets only via env.
- Dependencies listed explicitly (YAML library switched to the maintained `go.yaml.in/yaml/v3`).

Decisions made:
- Primary deployment: **Docker on NAS/server**. The Docker milestone moved to 4, the Windows prober moved to 7, and armv7 builds were added.
- IPv4 first with a family-agnostic design; IPv6 prober later.
- Added scope: overview page, 30d/90d/custom ranges with drag-to-zoom, TLS cert-expiry rule, DNS resolver probe, silences and maintenance windows, optional heartbeat.
- Not planned: Prometheus metrics. Data export (CSV/JSON) and the printable ISP report were added later (issue #22).
- Remote access: Basic auth required off loopback, optional built-in TLS; no unauthenticated mode.
- License: MIT.
