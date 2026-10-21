# php2mon

Live monitor for exploitation of PHP2Shell (CVE-2026-109618 and
CVE-2026-109619), the PHP runtime flaws disclosed on 2026-10-21.

It combines a self-hosted decoy sensor with public feeds (SANS ISC, Cloudflare
Radar, CISA KEV, GitHub, Shodan) and presents them as a self-updating
dashboard. Everything runs from one Docker Compose file on a small VM.

Code, schemas, and dashboard layout are public. The decoy's persona, detection
signatures, and deployment details are kept in a separate private repository
and mounted at runtime; `config.example/` shows the file shapes.

Status: design complete, implementation starting.

Data credits: SANS Internet Storm Center (CC BY-NC-SA 4.0), Cloudflare Radar
(CC BY-NC 4.0), DB-IP lite (CC BY 4.0).
