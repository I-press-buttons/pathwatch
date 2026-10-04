-- pathwatch schema v3: index for the outbox sender's polling queries.
--
-- DueOutbox and NextOutboxDue (every 5 s) select the rows with status IN ('queued','retrying').
-- No index covered that: outbox_pending is keyed by next_attempt_at alone and partial on
-- delivered_at, which those predicates do not imply, so each poll scanned the whole table, and
-- delivered rows are kept as the alerts feed history. With this index a poll reads only the
-- pending rows.

CREATE INDEX outbox_status ON outbox (status, next_attempt_at);
