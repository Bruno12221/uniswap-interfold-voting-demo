#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Source this file from bash. All tools and mutable build state stay in .local.
if [ -z "${BASH_VERSION:-}" ]; then
  printf '%s\n' 'Use bash to source scripts/t03/env.sh.' >&2
  return 1
fi
T03_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export T03_ROOT
export CARGO_HOME="$T03_ROOT/.local/cargo"
export RUSTUP_HOME="$T03_ROOT/.local/rustup"
export CARGO_INSTALL_ROOT="$T03_ROOT/.local/tools/rust"
export PATH="$T03_ROOT/.local/tools/bin:$CARGO_INSTALL_ROOT/bin:$CARGO_HOME/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.91.1
export CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0
export RAYON_NUM_THREADS=2
export BB_NUM_THREADS=2
export PNPM_HOME="$T03_ROOT/.local/tools/pnpm-home"
export npm_config_cache="$T03_ROOT/.local/npm-cache"
export OPENVM_SETUP_DIR="$T03_ROOT/.local/openvm"
# Use the upstream release build's supported archive pin. The reviewed lock owns the digest.
E3_CIRCUITS_ARCHIVE_SHA256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["circuitBundle"]["sha256"])' "$T03_ROOT/config/t03-tools.macos-arm64.json")"
export E3_CIRCUITS_ARCHIVE_SHA256
