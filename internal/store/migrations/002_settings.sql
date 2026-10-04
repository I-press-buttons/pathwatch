-- pathwatch schema v2: settings edited in the web UI.
--
-- targets.spec now holds the UI-edited definition of a target: the whole definition of a
-- UI target (as before), or, for a config-file target, a definition that overrides the file.

CREATE TABLE settings (
    key         TEXT PRIMARY KEY,                  -- defaults | status | alerts | dns_probes
    value       TEXT NOT NULL,                     -- JSON
    updated_at  INTEGER NOT NULL
);
