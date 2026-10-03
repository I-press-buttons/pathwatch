package config

// StarterConfig is written on first run when the config file does not exist.
const StarterConfig = `# pathwatch configuration (written on first start; edit freely).
# Docs: https://github.com/i-press-buttons/pathwatch
#
# Relative paths in this file are relative to the directory of this file.
# Environment overrides: PATHWATCH_CONFIG, PATHWATCH_DB, PATHWATCH_LISTEN,
# PATHWATCH_USER, PATHWATCH_PASSWORD.
# Targets can also be added, paused and removed in the web UI.

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
  http_interval: 30s
  dns_interval: 30s
  path_rediscovery: 5m
  max_hops: 30

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

# Alert rules are validated now; delivery (webhook/email) arrives in a later release.
alerts:
  rules:
    - name: http-down
      type: http_failure
      consecutive: 3
    - name: http-slow
      type: http_latency
      metric: total
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
  cooldown: 30m
  clear_ratio: 0.7
  # maintenance_windows:
  #   - name: isp-nightly
  #     days: [mon, tue, wed, thu, fri, sat, sun]
  #     start: "03:00"
  #     end: "04:00"
  #     timezone: America/New_York
  # heartbeat:
  #   url: ""                              # e.g. a healthchecks.io ping URL
  #   interval: 5m
  # notify:
  #   webhook:
  #     url_env: PATHWATCH_WEBHOOK_URL
  #     preset: discord                    # discord | slack | ntfy | generic
`
