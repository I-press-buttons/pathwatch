# pathwatch

A self-hosted, always-on network path monitor in the spirit of [PingPlotter](https://www.pingplotter.com/). pathwatch continuously traces the route to the destinations you care about, records per-hop latency and loss, and measures real HTTP/HTTPS request timing alongside it, so you can tell "a router is rate-limiting my pings" from "my connection is actually broken". It ships as a single static binary with an embedded web dashboard, and as a multi-arch Docker image built for Synology and other NAS devices.

## Features

- **PingPlotter-style hop grid**: hop, IP, hostname, sent/lost, loss %, min/avg/max/current/p95, jitter, and an inline latency bar for every hop on the path. Click a hop to graph it.
- **Path timeline**: a heatmap with one row per hop and one column per time bucket, with route changes and monitor gaps marked. Live updates over Server-Sent Events.
- **HTTP phase correlation**: HTTP/HTTPS probes record DNS, TCP connect, TLS, time to first byte and transfer time, shown on the same time axis as the hops. TCP connect and DNS probes are supported too.
- **Rate-limit-aware alerting**: end-to-end probes (HTTP, TCP, destination ICMP) are the arbiter. Loss or latency on an intermediate router alone never pages you. Alerts use rolling baselines, hysteresis, cooldowns, silences and maintenance windows, and are queued and retried so you still hear about an outage once connectivity returns. Webhook (Discord, Slack, ntfy, generic) and email channels.
- **MOS score** per target from latency, jitter and loss.
- **Themes**: Auto, Light, Dark, Midnight, Nord, Solarized Light/Dark, High Contrast and a Classic green/yellow/red scale.
- **Long-term history** in SQLite with automatic rollups and retention.
- **Targets from the UI or a YAML file**: add, pause and remove targets in the browser, or keep them in version-controlled config.
- **Pure Go, no CGO**: runs on Linux (amd64, arm64, armv7) and Windows, with no runtime to install.

<!-- screenshots -->
## Screenshots

Screenshots use demo data.

| Target page (Classic theme) | Overview (Dark theme) |
|---|---|
| ![Target page](docs/screenshots/target-classic.png) | ![Overview](docs/screenshots/overview-dark.png) |

Nine built-in themes: Auto, Light, Dark, Midnight, Nord, Solarized Light, Solarized Dark, High Contrast, and Classic (PingPlotter-style green/yellow/red scale). Pick one from the header; the choice is remembered per browser.
<!-- /screenshots -->

## Quick start (Docker)

```sh
docker run -d --name pathwatch \
  --network host \
  --cap-add NET_RAW \
  --restart unless-stopped \
  -e TZ=Europe/London \
  -e PATHWATCH_PASSWORD='choose-a-long-password' \
  -v pathwatch-data:/data \
  ghcr.io/i-press-buttons/pathwatch:latest
```

Then open <http://localhost:8095> (or `http://<server-ip>:8095`) and log in as `admin`.

- `--network host` makes probes leave the machine directly, so the traced path is the path your real traffic takes. It also means the web UI is served on the host's own address, so no `-p` option is needed.
- `--cap-add NET_RAW` allows raw ICMP sockets for hop tracing.
- `/data` holds the config file, the database and the generated password. On first run a starter config with a few example targets is created. Keep it on local disk, not a network share.
- If you leave out `PATHWATCH_PASSWORD`, a random password is generated, saved to `/data/.pathwatch-password` and printed in the container log.

**Synology / Portainer:** follow the step-by-step guide in [docs/SYNOLOGY.md](docs/SYNOLOGY.md) and paste [deploy/portainer-stack.yml](deploy/portainer-stack.yml) into a Portainer stack. For plain Docker Compose see [deploy/docker-compose.yml](deploy/docker-compose.yml).

### Image tags

`ghcr.io/i-press-buttons/pathwatch` is published for `linux/amd64` and `linux/arm64`.

| Tag | Meaning |
|---|---|
| `latest` | Newest build of the default branch |
| `edge` | Newest build of any other branch |
| `1.2.3`, `1.2` | Releases |
| `sha-<short>` | A specific commit |

## Configuration

Settings live in a single YAML file with strict decoding (unknown keys are errors). In Docker it is `/data/pathwatch.yaml`; when run natively, pass `--config`. See the [config example in docs/SPEC.md](docs/SPEC.md#config-example) for every option: targets and probes, defaults, alert rules, maintenance windows, webhook and email channels, retention and TLS. Secrets such as webhook URLs and SMTP passwords are read from environment variables, never from the file.

Renaming a target starts a new history, because the target name is its identity in the database. Changing its `host` starts a new path version.

### Environment variables

| Variable | Default (Docker image) | Purpose |
|---|---|---|
| `PATHWATCH_CONFIG` | `/data/pathwatch.yaml` | Path to the config file. Created with a starter config if missing. |
| `PATHWATCH_DB` | `/data/pathwatch.db` | SQLite database path (overrides `storage.path`). Must be on a local filesystem. |
| `PATHWATCH_LISTEN` | `0.0.0.0:8095` | Address and port for the web UI (overrides `listen`). |
| `PATHWATCH_USER` | `admin` | Web UI user name. |
| `PATHWATCH_PASSWORD` | _generated_ | Web UI password. If unset and the bind is not loopback, one is generated, stored in `/data/.pathwatch-password` and logged. |
| `TZ` | `UTC` | Time zone for logs and maintenance windows. |

The binary on its own defaults to listening on loopback only. Whenever it listens on a non-loopback address, HTTP Basic auth is always on. Without TLS, credentials cross the network in clear text, so use the built-in TLS options or a reverse proxy (Synology's built-in reverse proxy works well) for anything beyond a trusted LAN.

### Health check

`GET /healthz` needs no authentication and returns 200 while the scheduler and writer are healthy. The Docker image uses it for its built-in `HEALTHCHECK`, following the port in `PATHWATCH_LISTEN`.

## Command line

```
pathwatch run [--config pathwatch.yaml]   # default when no subcommand is given
pathwatch check-config [--config ...]     # validate the config and exit
pathwatch trace <host>                    # one-shot mtr-style trace to stdout
pathwatch version
```

Inside a container: `docker exec -it pathwatch pathwatch trace 1.1.1.1`.

## Building from source

Requires Go 1.26 or newer. No C toolchain is needed.

```sh
go build ./cmd/pathwatch
./pathwatch run --config pathwatch.yaml
```

Embed a version string the same way the release builds do:

```sh
go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" ./cmd/pathwatch
```

Build the Docker image locally with `docker build -t pathwatch .` (add `--build-arg VERSION=...`). Run the checks with `gofmt -l .`, `go vet ./...` and `go test ./...`.

On Linux, raw ICMP needs either root, `CAP_NET_RAW` (`sudo setcap cap_net_raw+ep ./pathwatch`) or a `net.ipv4.ping_group_range` that includes your group. On Windows no administrator rights are needed.

## Privacy

pathwatch has no telemetry and makes no calls to third-party services by default. It only contacts the targets you configure, and the webhook, email and heartbeat endpoints if you set them. Reverse DNS for hop addresses uses your system resolver and can be turned off. ASN enrichment is off by default and uses either a GeoLite2 database you supply or DNS-based lookups if you enable it. Private and CGNAT addresses are never looked up. Secrets are never logged.

## Documentation

- [docs/SYNOLOGY.md](docs/SYNOLOGY.md): Synology + Portainer deployment guide
- [docs/SPEC.md](docs/SPEC.md): design and full configuration example
- [docs/API.md](docs/API.md): JSON API used by the UI

## License

[MIT](LICENSE)
