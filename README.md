# Uniswap Interfold Voting Demo

A research prototype exploring encrypted preliminary governance polls with Interfold/CRISP.

Five synthetic voters submitted six encrypted inputs, including one replacement. The completed secure round produced a verified aggregate of **1, 2, 2**. The browser demonstration replays those saved ballots and their original proofs through the interface and coordinator.

This is an independent experiment. It does not count as an official Uniswap vote, move voter assets or execute governance proposals. Real UNI voting is not supported by the current design.

## What this project adds

- Historical read-only UNI scoring and deterministic eligibility manifests.
- Frozen round context and checks binding ballots, keys and results to it.
- Durable coordination, transcript checks, delivery retries and recovery.
- A local voting/results interface that labels saved-ballot replay explicitly.

Interfold/CRISP supplies the encryption, ballot circuits, protocol and computation/decryption proof systems. This project integrates those components; it does not introduce new cryptography.

## What was demonstrated

The recorded secure round passed client, committee, computation and threshold-decryption verification. The complete admitted input set binds to the result. All 50 plaintext output words were checked: three totals and 47 zeros.

The browser replay reuses the six saved receipts and original aggregate proof. A separate fresh browser ballot was proved and delivered. Chrome/Rabby also delivered an existing receipt through a real zero-value local transaction. Neither is presented as a fresh completed aggregate round.

See [results and measurements](docs/RESULTS.md), [architecture](docs/ARCHITECTURE.md) and [privacy limits](docs/PRIVACY.md).

## Run the source checks

Use bash on macOS arm64 or Linux x86_64 with Python 3.9+, git and internet access:

```sh
python3 scripts/t08/prepare_public_verifier.py
source .local/public-verifier-tools/env.sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
python3 research/t02_feasibility.py --check
```

Preparation installs checksum-pinned Node 22.23.3, pnpm 10.7.1 and Anvil 1.5.1 inside `.local`. These checks do not build the proving stack or generate proofs. All 34 unit tests and the saved feasibility checks pass.

Verifying the saved `1,2,2` result additionally requires the separately supplied evidence bundle. That bundle is not included in this source repository. A clone alone cannot independently verify the recorded tally or run the complete browser replay. The [reproduction guide](docs/REPRODUCTION.md) distinguishes source checks, saved-proof verification and prepared-stack browser replay.

## Limits

The demo uses one credit per slot, one operator controlling the committee, and local eligibility, randomness and availability fixtures. The CPU aggregate computation took about 26 hours on the measured VM. There is no independent security audit, production throughput result or live-network qualification.

Exact UNI precision, weighted single-choice constraints and inference from public totals remain unresolved. Encryption does not establish anonymity, permanent secrecy or protection from coercion. See [the feasibility assessment](docs/FEASIBILITY.md) and [historical voting rules](docs/VOTING-RULES.md).

This is a source-only research handoff. No hosted voting service, live pilot or official governance integration is provided.

## Source and licensing

Original integration source uses LGPL-3.0-only. See [LGPL](LICENSE.md), [companion GPL](COPYING), [reuse notices](THIRD_PARTY.md) and [contribution guidance](CONTRIBUTING.md). Upstream source, installed dependencies, tool binaries and generated builds are not vendored here.
