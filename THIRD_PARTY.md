# Source and reuse notices

Original integration modules, tests, fixtures, browser files and harness scripts use LGPL-3.0-only. The unmodified LGPL text is in LICENSE.md; its companion GPLv3 text is in COPYING.

The harness obtains the public [Interfold monorepo](https://github.com/theinterfold/interfold/tree/4ace535c1ff4d7897ec958a943cb45c55dc298a7) at commit `4ace535c1ff4d7897ec958a943cb45c55dc298a7` into ignored `.local/upstream/interfold`. Bundled CRISP components declare 0.26.0. Upstream source, history, dependencies and generated verifiers are not vendored here. Keep their copyright, license and third-party notices in that checkout. `patches/t03-local.patch` identifies local baseline modifications and retains the surrounding upstream notices. Harness adjustments are visible in the original integration scripts.

The code calls CRISP's SDK, SAFE commitment implementation, typed ballot helper and proof/receipt interfaces. It does not replace their encryption or tally logic. Interfold declares LGPL-3.0-only. No new license is granted to upstream work.

Direct runtime dependencies are ethers 6.17.0, poseidon-lite 0.3.0 and @zk-kit/lean-imt 2.2.4, each declaring MIT. Exact dependency versions/integrity values are in package.json and pnpm-lock.yaml. Their implementations and packaged notices are installed dependencies, not copied source.

Prepared-stack fixtures use upstream-installed OpenZeppelin EIP-712, @zk-kit LazyIMT and poseidon-solidity 0.0.5, which declare MIT. The browser build uses upstream Vite 5.4.21 and Buffer 6.0.3 (MIT), Playwright 1.52.0 (Apache-2.0), plus the matching CRISP, Noir, Barretenberg and WASM packages. Preserve all applicable notices when distributing a build. No generated browser bundle or downloaded tool executable is part of this source repository.

The independently authored UNI ABI contains method signatures for read-only interoperability. Snapshot's public scoring strategy is a behavioral reference. No Uniswap contract implementation, private participant data, branding assets or source from another private project is included.

The verification-only source contains ABI descriptions and trusted hashes, not the original deployed contract bytecode/state. The separate proof bundle includes that public synthetic state and is not distributed here. Before distributing compiled contracts, browser builds or that bundle, complete the corresponding-source, modification, build-information and third-party-notice review for those exact artifacts. This source handoff is not legal clearance for a binary distribution.
