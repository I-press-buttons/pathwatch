#!/bin/sh
# Container healthcheck: GET /healthz on the address pathwatch listens on.
# Derives host and port from PATHWATCH_LISTEN (default 0.0.0.0:8095) so a
# changed port is honoured. Wildcard binds are probed via loopback.
listen="${PATHWATCH_LISTEN:-0.0.0.0:8095}"
port="${listen##*:}"
host="${listen%:*}"
case "$host" in
  ""|"0.0.0.0"|"::"|"[::]") host="127.0.0.1" ;;
esac
exec wget -q -O- "http://${host}:${port}/healthz" >/dev/null
