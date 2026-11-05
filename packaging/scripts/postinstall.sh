#!/bin/sh
set -eu
groupadd --system --force gdns
if ! id -u gdns >/dev/null 2>&1; then
  nologin=$(command -v nologin || printf /bin/false)
  useradd --system --gid gdns --home-dir /var/lib/gdns --shell "$nologin" gdns
fi
install -d -o gdns -g gdns -m 0750 /var/lib/gdns
install -d -o root -g gdns -m 0750 /etc/gdns
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi
# Installation deliberately does not start a DNS service or alter the system resolver.
