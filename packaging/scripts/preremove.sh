#!/bin/sh
set -eu
# Debian passes remove/purge; RPM passes 0 only for final uninstall.
case "${1:-}" in
  remove|purge|0)
    if [ -d /run/systemd/system ]; then
      systemctl stop ghole.service || true
      systemctl disable ghole.service || true
    fi
    ;;
esac
# Preserve /var/lib/ghole and the service account, including on purge.
