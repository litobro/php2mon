# php2mon

Live monitor for exploitation of PHP2Shell (CVE-2026-109618 and
CVE-2026-109619), the PHP runtime flaws disclosed on 2026-10-21.

It combines a self-hosted decoy sensor with public feeds (SANS ISC, Cloudflare
Radar, CISA KEV, GitHub, Shodan) and presents them as a self-updating
dashboard. Everything runs from one Docker Compose file on a small VM.

Code, schemas, and dashboard layout are public. The decoy's persona, detection
signatures, and deployment details are kept in a separate private repository
and mounted at runtime; `config.example/` shows the file shapes.

Status: Plan 1 (decoy sensor) deployed; Plan 2 (collectors and dashboard) next.

Data credits: SANS Internet Storm Center (CC BY-NC-SA 4.0), Cloudflare Radar
(CC BY-NC 4.0), DB-IP lite (CC BY 4.0).

## Development

    uv sync
    uv run pytest -q

Integration tests that need Postgres run only when `DATABASE_URL` is set.

## Running the stack

    cp config.example/.env.example .env   # edit POSTGRES_PASSWORD
    docker compose up -d

The sensor listens on 80 and 443. Point `CONFIG_DIR` in `.env` at a directory
containing `persona.yaml`, `signatures.yaml`, and optionally `geoip/*.mmdb`.

## Deployment

`deploy/cloud-init.yaml` provisions an Ubuntu 24.04 host that clones this repo
and a private config repo, then runs `deploy/sync.sh` every five minutes to
pull changes and restart what changed. Images are built by CI and published to
`ghcr.io/litobro/php2mon-sensor`.
