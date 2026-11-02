# Reproduction

There are three distinct checks. None of the commands below generates an aggregate proof.

## Source checks

Requirements: bash, Python 3.9+, git, macOS arm64 or Linux x86_64, internet for pinned tools/npm packages.

```sh
python3 scripts/t08/prepare_public_verifier.py
source .local/public-verifier-tools/env.sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
python3 research/t02_feasibility.py --check
```

Preparation downloads checksum-pinned Node 22.23.3, pnpm 10.7.1 and Anvil 1.5.1 into ignored `.local`. Source tests require no SDK, circuits, Rust, proving keys, wallet or funded account. Keep npm package publishing disabled; package.json's private field is intentional.

## Verify the saved aggregate

Supply the separately obtained, reviewed `T08-Verified-Round-20261029` evidence directory. The 17-file bundle is not included in this source repository; there is no public download supplied here. Source tests alone do not verify the recorded tally.

After the preparation above, with loopback port 18592 free:

```sh
node scripts/t08/verify_public_bundle.mjs /absolute/path/to/T08-Verified-Round-20261029
```

Expected result: passed, 14 check groups, totals 1,2,2. The verifier checks bundle inventory/checksums, review-pinned runtime hashes and proxy targets, six original client proofs, census/key/transcript context, committee proof/attestations, computation seal/journal and threshold decryption. Three totals and all 47 zero padding words are checked. Runtime pins are trusted review inputs, not authenticated merely by a bundle's own checksum manifest.

It owns and stops a disposable loopback Anvil instance. No SDK build, Rust, proving keys or compiler is required. Do not expose this development chain to the network.

## Prepared-stack browser replay

This path additionally needs the matching built upstream stack, saved public chain export and original checked recovery material. Those are not shipped here. Upstream is pinned to Interfold `4ace535c1ff4d7897ec958a943cb45c55dc298a7` (`v0.19.0`, bundled CRISP 0.26.0). Matching circuits/verifiers, compiled source artifacts and OpenVM runtime identities must already be available. The older baseline build helpers in `scripts/t03/` are macOS arm64 development tools, not a complete automatic setup for the final secure replay.

The retained scripts show the application replay and its controls:

```sh
source scripts/t03/env.sh
python3 scripts/t08/extract_public_inputs.py /absolute/path/to/recovery/completed-round-evidence.tar.gz .local/runs/public-inputs/input.bin
node scripts/t08/replay_chain.mjs /absolute/path/to/public-chain-export .local/runs/application-replay --application /absolute/path/to/recovery .local/runs/public-inputs/input.bin
node scripts/t07/build.mjs
node scripts/t08/interface_replay.mjs .local/runs/application-replay --round-replay
```

The extractor needs the recovery's adjacent public manifest and SHA256SUMS file. It extracts one checksum-checked public ciphertext stream, not witnesses. Replay creates its own frozen context before original admissions; it preserves proof-bound identities rather than the original chain root.

Use `--verify` to check the completed page plus RPC outage, or `--serve` to inspect the completed result. `--vote` opens an isolated empty copy for receipt-delivery checks. That copy cannot display the old aggregate for new inputs. Default interface ports are 18709/18591; keep them loopback. T08_RPC_PORT and T08_HTTP_PORT select alternate free ports. Stop an interactive preview with Ctrl-C.

The old long-running proof controllers, VM transfer packages, repair scripts and internal build history are deliberately excluded from this source handoff. A fresh full-round build/proving benchmark is outside its reproduction claim. Preserve existing proofs; do not launch another long computation to inspect these results.
