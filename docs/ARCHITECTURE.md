# Architecture

The prototype is a coordination layer around the pinned Interfold/CRISP stack. It explores an independent, nonbinding preliminary poll; it is not connected to official voting transport or governance execution.

## Round flow

1. Rebuild eligibility and freeze proposal, chain, census, options, timing, parameters and deployment identities.
2. Authenticate the committee public key for that round.
3. Prepare and prove an encrypted ballot in the browser. Keep the choice and private witness in the client.
4. Commit the input and finalize availability of the exact ciphertext bytes. A replacement must refer to the correct parent.
5. Bind all admitted inputs into the transcript. Only the selected final contribution for each slot affects the tally.
6. Verify encrypted computation and committee decryption, then publish the aggregate.
7. Display verified totals only while the coordinator's round, deployment, proof and chain checks remain valid.

The secure browser demonstration replays the saved original inputs and proofs. It freezes context in a separate disposable application replay; it does not retroactively add that registry to the original VM chain. The replay preserves proof-bound identities rather than reproducing the original chain state root.

## Source map

| Area | Files |
| --- | --- |
| Scoring and census | `src/scoring.mjs`, `src/census.mjs`, `src/reference.mjs` |
| Round and ballot binding | `src/round.mjs`, `src/ballot-core.mjs`, `src/ballot.mjs`, `src/wallet.mjs` |
| Transcript and results | `src/transcript.mjs`, `src/coordinator-proofs.mjs`, `src/coordinator-policy.mjs` |
| Durable coordination | `src/coordinator.mjs`, `src/coordinator-store.mjs`, `src/coordinator-outbox.mjs` |
| Admission signer budget | `src/admission-budget.mjs` |
| Interface | `web/`, `src/interface.mjs`, `src/interface-server.mjs` |
| Frozen context contract | `contracts/FrozenRoundRegistry.sol` |
| Saved replay and verification | `scripts/t08/` |

The sole approved secure policy is the exact local synthetic replay in `config/t06-approved-secure-policies.json`, on chain 31337. Other policies remain rejected. The local callback durably reserves at most 60 distinct inputs before signing availability attestations, including wallet commitments. This depends on one guarded signing path and preserved database state; it does not change CRISP's protocol capacity of 100,000 or qualify a production signer.

## Why a separate application

The experiment needs a ballot interface, context binding and a verified result, without a DAO execution lifecycle. An Aragon plugin could suit a later chosen DAO deployment, but does not solve UNI precision, ballot constraints, public-output inference or operator compatibility. No Aragon plugin was implemented or required to demonstrate this coordination layer.

Real operation would need a reviewed voting/output design, qualified independent operators, real availability, all-path admission controls, practical proving performance and wallet/security review. No live trial or official adoption follows from these source checks.
