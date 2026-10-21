#!/bin/sh
# Runs every 5 minutes on the VM. Pulls both repos, then applies whatever
# changed: new images, new compose file, or new config.
set -eu
git -C /opt/php2mon-private pull -q --ff-only
git -C /opt/php2mon pull -q --ff-only
cd /opt/php2mon
cp /opt/php2mon/deploy/php2mon-sync.service /opt/php2mon/deploy/php2mon-sync.timer /etc/systemd/system/ && systemctl daemon-reload
docker compose pull -q
docker compose up -d --remove-orphans
docker image prune -f >/dev/null
