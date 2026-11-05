#!/bin/sh
set -eu
getent group ghole >/dev/null 2>&1 || groupadd --system ghole
if ! getent passwd ghole >/dev/null 2>&1; then
  nologin=$(command -v nologin || printf /bin/false)
  useradd --system --gid ghole --home-dir /var/lib/ghole --shell "$nologin" ghole
fi
install -d -o ghole -g ghole -m 0750 /var/lib/ghole
install -d -o root -g ghole -m 0750 /etc/ghole
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi
# Installation deliberately does not start a DNS service or alter the system resolver.
