#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export NODE_BACKEND="${NODE_BACKEND:-js}"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-$(mktemp -d)}"
trap 'rm -rf "$PYTHONPYCACHEPREFIX"' EXIT

python3 scripts/validate-hsrd-static.py
python3 scripts/validate-hsrd-source-handoff.py
python3 scripts/validate-work-fabric-source.py
python3 scripts/validate-operator-service-source.py
python3 scripts/validate-core-link-source.py
python3 scripts/validate-live-parent-and-unified-operator-source.py
node scripts/verify-operator-receipt-fixture.js

node hsd-oracle/audit-dependencies.js --allow-unavailable
npm run hsrd-script-fixtures --prefix hsd-oracle
npm run hsrd-deployment-fixtures --prefix hsd-oracle
npm run hsrd-mainnet-deployment-history --prefix hsd-oracle
npm run hsrd-airdrop-fixtures --prefix hsd-oracle
npm run hsrd-claim-fixtures --prefix hsd-oracle
npm run hsrd-mainnet-claim-history --prefix hsd-oracle
npm run hsrd-covenant-fixtures --prefix hsd-oracle
npm run hsrd-name-state-codec-fixtures --prefix hsd-oracle
npm run hsrd-name-state-urkel-fixtures --prefix hsd-oracle
npm run hsrd-name-policy-fixtures --prefix hsd-oracle
npm run hsrd-p2p-wire-fixtures --prefix hsd-oracle
npm run hsrd-mining-template-fixtures --prefix hsd-oracle
npm run core-vectors --prefix hsd-oracle
npm run validate-body --prefix hsd-oracle
npm run payout --prefix hsd-oracle

scripts/verify-hsrd-secp256k1.sh
scripts/verify-hsrd-goosig-source.sh

for source in \
  hsd-oracle/generate-hsrd-script-fixtures.js \
  hsd-oracle/generate-hsrd-deployment-fixtures.js \
  hsd-oracle/export-hsrd-mainnet-deployment-history.js \
  hsd-oracle/generate-hsrd-airdrop-fixtures.js \
  hsd-oracle/generate-hsrd-claim-fixtures.js \
  hsd-oracle/export-hsrd-mainnet-claim-history.js \
  hsd-oracle/generate-hsrd-covenant-fixtures.js \
  hsd-oracle/generate-hsrd-name-state-codec-fixtures.js \
  hsd-oracle/generate-hsrd-name-state-urkel-fixtures.js \
  hsd-oracle/generate-hsrd-name-policy-fixtures.js \
  hsd-oracle/generate-hsrd-p2p-wire-fixtures.js \
  hsd-oracle/generate-hsrd-mining-template-fixtures.js \
  scripts/verify-operator-receipt-fixture.js; do
  node --check "$source"
done

python3 -m py_compile \
  scripts/validate-hsrd-static.py \
  scripts/validate-hsrd-source-handoff.py \
  scripts/validate-work-fabric-source.py \
  scripts/validate-operator-service-source.py \
  scripts/validate-core-link-source.py \
  scripts/validate-live-parent-and-unified-operator-source.py

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --check
fi

if grep -RInE '^(<<<<<<< .+|={7}|>>>>>>> .+)$' \
  --exclude-dir=.git \
  --exclude-dir=node_modules \
  --exclude-dir=target \
  .; then
  echo "merge-conflict marker found" >&2
  exit 1
fi

echo "hsrd source handoff checks passed"
