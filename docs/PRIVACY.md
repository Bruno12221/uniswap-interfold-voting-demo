# Privacy and trust boundaries

The intended benefit is to keep individual choices encrypted while voters submit ballots and to release a verified final aggregate. The recorded synthetic round exercised real cryptographic verifiers; the wider operating environment remains a local fixture.

## What remains visible

Eligibility, addresses, public weights, slot metadata, ciphertexts, transaction senders and timing can be observable. RPC/service requests can expose network correlations. This application provides no network anonymity.

Public totals can reveal choices when weights, participation or other ballots are known. Unanimity, a dominant weight and subtraction of known contributions are simple examples. No universal turnout minimum guarantees secrecy. The [feasibility checks](FEASIBILITY.md) demonstrate these limits with synthetic data.

All committee nodes in the demo belong to one operator. A colluding decryption threshold or compromised threshold keys can undermine confidentiality beyond the intended aggregate release. A compromised browser can expose a ballot before encryption. No anonymity, permanent secrecy, bribery resistance or coercion-resistance claim is made.

## Application controls

The browser prepares private witness material locally. Only the public proof/ciphertext envelope is delivered. Bounded browser payload checks found no private choice/witness fields in submitted API bodies; this is not a general privacy audit.

Context checks bind proposal/census, deployment, committee key, parameters, slot, parent and ciphertext to the accepted round. The signer checks the ciphertext's SAFE commitment before reserving quota or attesting. The coordinator rejects incomplete or mismatched proof/transcript evidence. RPC failures or stale/unapproved results suppress verified totals.

The decryption output was checked in full: three aggregate totals and 47 zero coefficients, not one plaintext slot per voter. Secure masking/withdrawal was absent from this six-input aggregate; earlier component tests do not broaden that result.

The loopback server is a development tool. Public hosting, production authentication, real availability, independent operators, fresh Rabby Ballot authorization and mobile/browser compatibility have not been qualified. Use synthetic inputs only and keep private ballots, keys, witnesses and logs out of Git.
