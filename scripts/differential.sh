#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
vector_count=${1:-10000}

NODE_BACKEND=js node "$repo_dir/hsd-oracle/generate-vectors.js" --count "$vector_count" \
  | cargo run --locked --quiet \
      --manifest-path "$repo_dir/Cargo.toml" \
      -p meshmine-hns \
      --features vector-verifier \
      --bin verify-hsd-vectors
