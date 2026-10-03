-- pathwatch schema v1. All timestamps are Unix microseconds (UTC).

CREATE TABLE targets (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    host        TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,       -- 0 = removed from config
    source      TEXT NOT NULL DEFAULT 'config',   -- config | ui
    paused      INTEGER NOT NULL DEFAULT 0,
    spec        TEXT,                              -- JSON of the resolved spec (ui targets)
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- target_id 0 = not bound to a target (DNS resolver probes)
CREATE TABLE probes (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER NOT NULL,
    type       TEXT NOT NULL,
    key        TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    UNIQUE (target_id, key)
);

CREATE TABLE paths (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER NOT NULL,
    resolved_ip TEXT NOT NULL,
    dest_ttl    INTEGER NOT NULL DEFAULT 0,        -- 0 = destination never answered ICMP
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER
);
CREATE INDEX paths_target ON paths (target_id, started_at);

-- responder set per TTL; idx is the stable 0-based position used by the round blobs (blob stores idx+1)
CREATE TABLE path_hops (
    path_id  INTEGER NOT NULL,
    ttl      INTEGER NOT NULL,
    idx      INTEGER NOT NULL,
    address  TEXT NOT NULL,
    share    REAL NOT NULL DEFAULT 1,
    PRIMARY KEY (path_id, ttl, idx)
) WITHOUT ROWID;

CREATE TABLE ip_info (
    address    TEXT PRIMARY KEY,
    hostname   TEXT,
    asn        INTEGER,
    as_name    TEXT,
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;

-- one row per (target, round); results = packed per-TTL blob
CREATE TABLE icmp_rounds (
    target_id  INTEGER NOT NULL,
    ts         INTEGER NOT NULL,
    path_id    INTEGER NOT NULL,
    hop_count  INTEGER NOT NULL,
    results    BLOB NOT NULL,
    PRIMARY KEY (target_id, ts)
) WITHOUT ROWID;

CREATE TABLE http_samples (
    probe_id       INTEGER NOT NULL,
    ts             INTEGER NOT NULL,
    resolved_ip    TEXT,
    status         INTEGER,
    dns_us         INTEGER,
    connect_us     INTEGER,
    tls_us         INTEGER,
    ttfb_us        INTEGER,
    transfer_us    INTEGER,
    total_us       INTEGER,
    redirects      INTEGER,
    cert_not_after INTEGER,
    error          TEXT,
    PRIMARY KEY (probe_id, ts)
) WITHOUT ROWID;

CREATE TABLE tcp_samples (
    probe_id    INTEGER NOT NULL,
    ts          INTEGER NOT NULL,
    resolved_ip TEXT,
    connect_us  INTEGER,
    error       TEXT,
    PRIMARY KEY (probe_id, ts)
) WITHOUT ROWID;

CREATE TABLE dns_samples (
    probe_id INTEGER NOT NULL,
    ts       INTEGER NOT NULL,
    rcode    INTEGER,
    rtt_us   INTEGER,
    error    TEXT,
    PRIMARY KEY (probe_id, ts)
) WITHOUT ROWID;

-- monitor gaps: process stopped, host suspended, clock jump. "No data", never loss.
CREATE TABLE gaps (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER NOT NULL,
    reason     TEXT
);
CREATE INDEX gaps_target ON gaps (target_id, started_at);

-- rollups: 1-minute and 1-hour have the same shape. hist = sparse log-scale histogram blob.
CREATE TABLE icmp_rollup_1m (
    target_id INTEGER NOT NULL,
    bucket    INTEGER NOT NULL,
    ttl       INTEGER NOT NULL,
    path_id   INTEGER NOT NULL,
    n         INTEGER NOT NULL,
    lost      INTEGER NOT NULL,
    rtt_min   REAL,
    rtt_avg   REAL,
    rtt_max   REAL,
    jitter    REAL,
    hist      BLOB,
    PRIMARY KEY (target_id, bucket, ttl, path_id)
) WITHOUT ROWID;
CREATE TABLE icmp_rollup_1h (
    target_id INTEGER NOT NULL,
    bucket    INTEGER NOT NULL,
    ttl       INTEGER NOT NULL,
    path_id   INTEGER NOT NULL,
    n         INTEGER NOT NULL,
    lost      INTEGER NOT NULL,
    rtt_min   REAL,
    rtt_avg   REAL,
    rtt_max   REAL,
    jitter    REAL,
    hist      BLOB,
    PRIMARY KEY (target_id, bucket, ttl, path_id)
) WITHOUT ROWID;

CREATE TABLE probe_rollup_1m (
    probe_id       INTEGER NOT NULL,
    bucket         INTEGER NOT NULL,
    n              INTEGER NOT NULL,
    errors         INTEGER NOT NULL,
    dns_avg        REAL,
    connect_avg    REAL,
    tls_avg        REAL,
    ttfb_avg       REAL,
    transfer_avg   REAL,
    total_min      REAL,
    total_avg      REAL,
    total_max      REAL,
    hist           BLOB,
    cert_not_after INTEGER,
    PRIMARY KEY (probe_id, bucket)
) WITHOUT ROWID;
CREATE TABLE probe_rollup_1h (
    probe_id       INTEGER NOT NULL,
    bucket         INTEGER NOT NULL,
    n              INTEGER NOT NULL,
    errors         INTEGER NOT NULL,
    dns_avg        REAL,
    connect_avg    REAL,
    tls_avg        REAL,
    ttfb_avg       REAL,
    transfer_avg   REAL,
    total_min      REAL,
    total_avg      REAL,
    total_max      REAL,
    hist           BLOB,
    cert_not_after INTEGER,
    PRIMARY KEY (probe_id, bucket)
) WITHOUT ROWID;

-- annotations (state transitions only): route_change, rate_limited, degraded, icmp_unresponsive,
-- gap, local_outage. target_id NULL = global. ended_at NULL = instant or still open.
CREATE TABLE events (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER,
    kind       TEXT NOT NULL,
    ttl        INTEGER,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER,
    details    TEXT
);
CREATE INDEX events_target ON events (target_id, started_at);
CREATE INDEX events_open ON events (kind) WHERE ended_at IS NULL;

-- alert engine tables (populated by internal/alert in a later phase)
CREATE TABLE alerts (
    id                INTEGER PRIMARY KEY,
    target_id         INTEGER,
    rule              TEXT NOT NULL,
    rule_type         TEXT NOT NULL,
    state             TEXT NOT NULL,              -- firing | resolved | suppressed
    suppressed_reason TEXT,                       -- silence | maintenance | local_outage | cooldown
    started_at        INTEGER NOT NULL,
    ended_at          INTEGER,
    value             REAL,
    peak_value        REAL,
    baseline          REAL,
    message           TEXT,
    details_json      TEXT
);
CREATE INDEX alerts_target ON alerts (target_id, started_at);
CREATE INDEX alerts_state ON alerts (state);

-- persistent outbox: survives restarts, retried with backoff until delivered or expired
CREATE TABLE outbox (
    id              INTEGER PRIMARY KEY,
    alert_id        INTEGER NOT NULL,
    channel         TEXT NOT NULL,
    payload         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued',   -- queued | delivered | retrying | failed | expired
    created_at      INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER,
    delivered_at    INTEGER,
    last_error      TEXT
);
CREATE INDEX outbox_alert ON outbox (alert_id);
CREATE INDEX outbox_pending ON outbox (next_attempt_at) WHERE delivered_at IS NULL;

CREATE TABLE silences (
    id         INTEGER PRIMARY KEY,
    target_id  INTEGER,                              -- NULL = all targets
    rule       TEXT,                                 -- NULL = all rules
    starts_at  INTEGER NOT NULL,
    ends_at    INTEGER NOT NULL,
    reason     TEXT,
    created_by TEXT
);
CREATE INDEX silences_ends ON silences (ends_at);
