# Recorded results

The completed secure synthetic round was reviewed on 29 October 2026. Five voters, ten eligible slots, three choices and six admitted inputs (including one replacement) produced **1, 2, 2**. All 50 output words were checked: three totals and 47 zeros.

## Evidence scope

Actual client, committee, computation and threshold-decryption proofs passed. The approved profile is secure-8192, parameter set 2, degree 8,192 and plaintext modulus 17,000,000. The committee has three nodes, with two decryption shares checked. One operator controls every node. Eligibility, randomness and availability are local fixtures.

The application replay reconstructs the census, authenticates the public key, freezes context before admissions and delivers the six saved receipts through the browser. It rebuilds the original input root and accepts the original computation/decryption proofs. The page explicitly labels this Saved-ballot replay. This is not a fresh completed browser voting round.

A separate fresh browser-client proof was generated and its public receipt delivered after a retry. Chrome/Rabby delivery of an existing receipt reached Availability confirmed and matched a real zero-value local transaction. A fresh Rabby typed Ballot signature, other providers/mobile and secure masking/withdrawal within this aggregate remain unqualified.

Recorded checks included 51 saved-proof groups, 21 source/artifact runtime matches, 43 lifecycle groups replaying 172 original signed transactions, 17 application/coordinator groups, six browser-replay groups and four browser RPC-outage groups. The lightweight verifier checks 22 pinned runtime identities in 14 groups. Runtime/proxy substitutions were also rejected after bundle hashes were recomputed. These counts are automated check groups, not independent audits.

[Application evidence](reference/t08-application-evidence.json) records the exact scope and local synthetic transaction identities. [Secure-round evidence](reference/t08-secure-round-evidence.json) preserves the earlier original-round observations; later application checks extend that dated record. The full proof/state bundle is separate and is not shipped here.

## Measured CPU computation

The VM reported 16 logical CPUs, 15 proving threads, eight compression threads and approximately 26.6 GB RAM. Sampled total owned-process peak was about 20.5 GB, not a hard memory peak.

| Stage | Seconds |
| --- | ---: |
| Application proof | 68,082.50 |
| Recursive STARK aggregation | 24,498.72 |
| Root proof | 167.94 |
| Final compression | 911.97 |
| Total | 93,661.13, about 26 hours |

Client admission measurements were 241–265 seconds each, including submission/finalization waiting; they are not isolated proof benchmarks. GPU acceleration and larger electorates were not benchmarked. The measured latency is a practical limitation.

## Local transaction gas

| Operation | Total gas |
| --- | ---: |
| Round request | 2,653,275 |
| Committee publication | 3,663,725 |
| Six input commitments | 19,825,854 |
| Six local availability finalizations | 88,344,810 |
| Aggregate ciphertext publication | 14,793,210 |
| Plaintext publication | 3,941,720 |

The entire captured setup and round used 268,057,067 gas, including 51 deployments. Raw-ciphertext availability fixtures and local chain rules make these unsuitable as a mainnet fee quote.

The semantic lifecycle replay prefunds synthetic senders and omits 99,840 empty proving-wait blocks. Block hashes/PREVRANDAO differ; only the unused E3 computation-seed event field is normalized. It is not original chain-root reproduction. No mainnet, testnet or official governance pilot is claimed.
