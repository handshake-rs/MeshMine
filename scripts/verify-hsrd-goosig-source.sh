#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ORACLE="$ROOT/hsd-oracle/node_modules/goosig"
VENDOR="$ROOT/hsrd/vendor/goosig"

if [[ ! -f "$ORACLE/package.json" ]]; then
  echo "pinned Goosig oracle dependency is unavailable; run npm ci --prefix hsd-oracle --ignore-scripts" >&2
  exit 1
fi

version="$(node -p "require(process.argv[1]).version" "$ORACLE/package.json")"
if [[ "$version" != "0.11.0" ]]; then
  echo "expected pinned Goosig 0.11.0, got $version" >&2
  exit 1
fi

files=(
  LICENSE
  src/goo/drbg.c
  src/goo/drbg.h
  src/goo/goo.c
  src/goo/goo.h
  src/goo/hmac.c
  src/goo/hmac.h
  src/goo/internal.h
  src/goo/mini-gmp.c
  src/goo/mini-gmp.h
  src/goo/primes.h
  src/goo/sha256.c
  src/goo/sha256.h
  src/goo/util.h
)

for file in "${files[@]}"; do
  cmp "$ORACLE/$file" "$VENDOR/$file"
done

echo "vendored Goosig 0.11.0 source matches the pinned HSD dependency"
