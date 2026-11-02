#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "$T03_ROOT"
python3 scripts/t03/prepare.py
mkdir -p .local/logs
cd .local/upstream/interfold
test "$(git rev-parse HEAD)" = 4ace535c1ff4d7897ec958a943cb45c55dc298a7
git apply --reverse --check "$T03_ROOT/patches/t03-local.patch"
# The setup installs only into CARGO_INSTALL_ROOT from env.sh. It starts no services.
/usr/bin/time -l pnpm --filter @crisp-e3/main dev:setup > "$T03_ROOT/.local/logs/t03-setup.log" 2>&1
# The upstream dev compile script does not request --locked. Keep the T03 build locked.
pnpm --filter @crisp-e3/main exec cargo build --locked -p e3-support-scripts-dev --bin e3-support-scripts-dev \
  > "$T03_ROOT/.local/logs/t03-dev-build.log" 2>&1
pnpm openvm prover-check > "$T03_ROOT/.local/logs/t03-secure-prover-check.log" 2>&1
echo 'T03 baseline build and secure worker compile check passed. No round has run yet.'
