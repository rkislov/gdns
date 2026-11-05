#!/bin/sh
set -eu
# Debian passes remove/purge; RPM passes 0 only for final uninstall.
case "${1:-}" in
  remove|purge|0)
    if [ -d /run/systemd/system ]; then
      systemctl stop gdns.service || true
      systemctl disable gdns.service || true
    fi
    ;;
esac
# Preserve /var/lib/gdns and the service account, including on purge.
