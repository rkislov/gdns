#!/bin/bash
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
# Run as root on the explicitly authorized development server after reviewing.
set -euo pipefail
stage=${1:?staging directory required}
[[ "$(id -u)" == 0 ]]
[[ -f "$stage/ghole.deb" ]]
if systemctl is-active --quiet ghole; then
  printf 'Existing GHole service found; use an explicit upgrade procedure.\n' >&2
  exit 1
fi
dpkg -i "$stage/ghole.deb"
install -d -o root -g ghole -m 0750 /etc/ghole/tls
install -o root -g ghole -m 0640 /etc/letsencrypt/live/dev.kislovs.ru/fullchain.pem /etc/ghole/tls/fullchain.pem
install -o root -g ghole -m 0640 /etc/letsencrypt/live/dev.kislovs.ru/privkey.pem /etc/ghole/tls/privkey.pem
STAGE="$stage" python3 - <<'PY'
import ipaddress,json,os
from pathlib import Path
# Export defaults with the application, then adjust only deployment settings.
import subprocess
path=Path('/var/lib/ghole/config.json')
if path.exists() or Path('/var/lib/ghole/ghole.db').exists():
    raise SystemExit('Refusing to overwrite an existing configuration/database')
subprocess.run(['/usr/bin/ghole','-config','/var/lib/ghole/bootstrap.json','-database','/var/lib/ghole/bootstrap.db','-export-config',str(path)],check=True)
c=json.loads(path.read_text())
c.update(dns_listen='45.87.247.8:53',http_listen='127.0.0.1:8080',doh_listen='0.0.0.0:443',dot_listen='0.0.0.0:853',tls_cert_file='/etc/ghole/tls/fullchain.pem',tls_key_file='/etc/ghole/tls/privkey.pem')
peer=ipaddress.ip_address((Path(os.environ['STAGE'])/'ssh-peer.txt').read_text().split()[0])
c['allowed_clients']+=['45.87.247.8/32',str(peer)+('/32' if peer.version==4 else '/128')]
path.write_text(json.dumps(c,indent=2)+'\n');path.chmod(0o600)
PY
chown -R ghole:ghole /var/lib/ghole
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/ghole-tls.sh <<'HOOK'
#!/bin/sh
set -eu
[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/dev.kislovs.ru ] || exit 0
install -o root -g ghole -m 0640 "$RENEWED_LINEAGE/fullchain.pem" /etc/ghole/tls/fullchain.pem
install -o root -g ghole -m 0640 "$RENEWED_LINEAGE/privkey.pem" /etc/ghole/tls/privkey.pem
systemctl try-restart ghole.service
HOOK
chmod 0750 /etc/letsencrypt/renewal-hooks/deploy/ghole-tls.sh
systemctl daemon-reload
systemctl enable --now ghole.service
systemctl --no-pager --full status ghole.service
