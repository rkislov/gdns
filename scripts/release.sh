#!/bin/sh
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
set -eu
VERSION=${VERSION:-0.5.0}
COMMIT=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || printf unknown)}
BUILD_DATE=${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
NFPM=${NFPM:-nfpm}
export VERSION
mkdir -p dist
for ARCH in amd64 arm64; do
  export ARCH
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath \
    -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
    -o "dist/gdns_linux_$ARCH" ./cmd/gdns
  stage=$(mktemp -d)
  cp "dist/gdns_linux_$ARCH" "$stage/gdns"
  cp LICENSE NOTICE THIRD_PARTY_NOTICES.txt README.md docs/linux-installation.md "$stage/"
  tar -C "$stage" -czf "dist/gdns_${VERSION}_linux_${ARCH}.tar.gz" .
  for DISTRO in altlinux redos astra; do
    export DISTRO
    format=rpm
    if [ "$DISTRO" = astra ]; then format=deb; fi
    python3 - <<'PYCONFIG'
import os
from pathlib import Path
Path('dist/nfpm-generated.yaml').write_text(os.path.expandvars(Path('packaging/nfpm.yaml').read_text()))
PYCONFIG
    "$NFPM" package --config dist/nfpm-generated.yaml --packager "$format" \
      --target "dist/gdns_${VERSION}_${DISTRO}_${ARCH}.${format}"
  done
done
python3 - <<'PY'
from pathlib import Path
import hashlib
files=sorted(p for p in Path('dist').iterdir() if p.suffix in ('.gz','.rpm','.deb'))
Path('dist/SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in files))
PY
