package config

// StarterConfig is written on first run when the config file does not exist.
const StarterConfig = `# pathwatch configuration (written on first start; edit freely).
# Docs: https://github.com/i-press-buttons/pathwatch
#
# Relative paths in this file are relative to the directory of this file.
# Environment overrides: PATHWATCH_CONFIG, PATHWATCH_DB, PATHWATCH_LISTEN,
# PATHWATCH_USER, PATHWATCH_PASSWORD.
# Targets can also be added, edited, paused and removed in the web UI.
# Settings changed in the web UI (Settings page, target editor) are stored in the
# database and take precedence over this file; the UI can revert them to this file.

# Address to serve the web UI on. When this is not a loopback address, Basic auth
# is always on: set PATHWATCH_PASSWORD, or pathwatch generates a password and
# stores it in .pathwatch-password next to the database.
listen: 127.0.0.1:8080
# public_url: https://nas.local:8080     # used for deep links in alerts

# auth:
#   basic_user: admin                     # default; or PATHWATCH_USER
#   basic_password_env: PATHWATCH_PASSWORD

# tls:                                    # optional built-in HTTPS
#   cert_file: tls/cert.pem
#   key_file: tls/key.pem

log:
  level: info                             # debug | info | warn | error
  format: text                            # text | json
  # file: pathwatch.log                   # optional

storage:
  path: pathwatch.db                      # must be on a local filesystem (not NFS/SMB)
  raw_retention: 7d
  rollup_1m_retention: 90d
  rollup_1h_retention: 0                  # 0 = keep forever

probing:
  icmp_mode: auto                         # auto | raw | dgram (Linux)

enrich:
  reverse_dns: true
  # asn_db: GeoLite2-ASN.mmdb             # optional, user-supplied MaxMind database

defaults:                                 # inherited by every target/probe
  icmp_interval: 2s
  icmp_timeout: 2s
  tcp_interval: 10s
  tcp_timeout: 5s
  http_interval: 30s
  http_timeout: 10s
  dns_interval: 30s
  dns_timeout: 3s
  path_rediscovery: 5m
  max_hops: 30
  retries: 0                              # retry failed HTTP/TCP/DNS probes (0-10); ICMP never retries

# Targets: host is a hostname (FQDN such as example.com), an IPv4 or an IPv6 address.
# Hop tracing is IPv4-only for now; HTTP and TCP probes work over IPv6 too.

status:                                   # when a target shows as "degraded"
  degraded_loss_pct: 5                    # end-to-end loss above this (last 5 minutes)
  degraded_http_success_pct: 95           # HTTP success rate below this (last 5 minutes)

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
  - name: cloudflare-dns
    host: 1.1.1.1
    probes:
      - type: icmp-trace
  - name: google-dns
    host: 8.8.8.8
    probes:
      - type: icmp-trace

# dns_probes:
#   - name: home-resolver
#     server: 192.168.1.1:53
#     query: example.com
#     record: A

# Alerting. Rules apply to every target that has the probes a rule needs.
# Targets can disable rules or override parameters:
#   alerts:
#     disable: [route_change]
#     override:
#       end-loss: { threshold_pct: 10 }
# Alerts show up in the web UI without any channel configured; add a webhook
# and/or email below to be notified. Notifications are queued in the database
# and retried for up to outbox.max_age, so alerts about your own outage arrive
# once the connection is back.
alerts:
  rules:
    - name: http-down
      type: http_failure
      consecutive: 3
    - name: http-slow
      type: http_latency
      metric: total                      # total | ttfb
      baseline_window: 24h
      min_baseline: 2h                   # inactive until this much history exists
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
      enabled: false                     # notify whenever the path changes
      # notify: [webhook]                # per-rule channel routing (default: all)
  cooldown: 30m
  clear_ratio: 0.7
  # maintenance_windows:
  #   - name: isp-nightly
  #     days: [mon, tue, wed, thu, fri, sat, sun]
  #     start: "03:00"
  #     end: "04:00"
  #     timezone: America/New_York
  # heartbeat:                           # dead-man's switch, pinged while healthy
  #   url: ""                            # e.g. a healthchecks.io ping URL
  #   interval: 5m
  # outbox:
  #   max_age: 24h                       # give up on undelivered notifications after this
  #
  # Webhook: the URL is a secret and is read from an environment variable.
  # Presets: generic (JSON, for n8n / Home Assistant), discord, slack, ntfy.
  # notify:
  #   webhook:
  #     url_env: PATHWATCH_WEBHOOK_URL   # export PATHWATCH_WEBHOOK_URL=https://...
  #     preset: generic                  # generic | discord | slack | ntfy
  #     # headers:                       # values may reference environment variables
  #     #   Authorization: "Bearer ${NTFY_TOKEN}"
  #     # body_template: |               # Go text/template; replaces the preset body
  #     #   {"text": {{json .Title}}, "state": "{{.State}}", "link": "{{.Link}}"}
  #     #   Discord templates must use {{json .Message}} and include
  #     #   "allowed_mentions": {"parse": []} so alert text can never ping anyone.
  #
  #   Examples (set one preset):
  #     discord:  url_env -> https://discord.com/api/webhooks/<id>/<token>
  #     slack:    url_env -> https://hooks.slack.com/services/T000/B000/XXXX
  #     ntfy:     url_env -> https://ntfy.sh/<your-topic>  (add an Authorization header if protected)
  #
  #   email:
  #     smtp_host: smtp.example.com
  #     smtp_port: 587                   # 587 starttls, 465 tls, 25 none
  #     tls: starttls                    # starttls | tls | none
  #     username_env: SMTP_USER
  #     password_env: SMTP_PASSWORD
  #     from: pathwatch@example.com
  #     to: [you@example.com]
`
