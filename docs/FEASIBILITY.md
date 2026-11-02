# Real-UNI feasibility

The current design supports a bounded synthetic demonstration. It does not support a responsible claim of private, exact UNI voting.

## Three unresolved issues

**Exact units.** Native UNI uses 18-decimal raw integer weights and a historical voting interface that differs from generic Votes tokens. In the pinned secure BFV preset each coefficient is reduced modulo 17,000,000. A uint64 output container does not increase that plaintext capacity. One UNI is 10^18 raw units and cannot be represented exactly in the default single-coefficient rule. Scaling or rounding would change the selected voting rules.

**Single-choice constraints.** At the pinned revision, weighted option totals may be at most the balance rather than requiring its full use. More-than-two-option configurations do not generally enforce a full-weight single choice. With credit 1, nonnegative integer options summing to at most 1 permit one choice or zero contribution, which is the approved synthetic profile. Arbitrary unequal weights are not qualified.

**Output inference.** Even correct exact aggregate totals can identify choices when public weights and other information narrow the possibilities. With weights 1, 2, 4, 8, 16, 32, 64 and 128, a FOR total of 37 uniquely selects weights 1, 4 and 32 under a known full-participation binary roster. Equal weights still permit unanimity and known-ballot subtraction attacks. These examples are synthetic, not an attack on real participants.

A researched base-128 digit encoding fits the arithmetic bounds for two/three choices but publishes uncarried digit sums. For weights 1, 127 and 128, the alternatives FOR {1,127} and FOR {128} have the same scalar total; the digit sums distinguish them. This encoding therefore leaks more and is not approved. Hiding those intermediate values after decryption is too late.

## Reproduce the research

```sh
python3 research/t02_feasibility.py --check
```

The original script and [saved synthetic evidence](reference/t02-evidence.json) cover seven inference fixtures, the additional digit-sum disclosure, integer encodings/group sums, maximum bounds and actual JavaScript floating-point precision collisions. These are arithmetic models, not execution of BFV or Noir.

Historical scoring reads preserve raw integers. The inspected Snapshot strategy converts formatted units to floating point, so exact-integer semantics are not automatically bit-for-bit historical display-score parity. Five public reference cases were checked; no complete real-UNI electorate is provided. See [the reference rules](VOTING-RULES.md) and [reference evidence](reference/t04-evidence.json).

A real-UNI trial needs a separately reviewed exact-weight/single-choice/output design, privacy analysis for the intended electorate, supported operators and practical performance. None of these requirements is removed by linking a ballot site or adding a DAO plugin.

## Pinned source

This assessment concerns Interfold `4ace535c1ff4d7897ec958a943cb45c55dc298a7` (`v0.19.0`, bundled CRISP `0.26.0`), not a claim about every later release.

- [Parameters](https://github.com/theinterfold/interfold/blob/4ace535c1ff4d7897ec958a943cb45c55dc298a7/crates/fhe-params/src/constants.rs)
- [CRISP contract](https://github.com/theinterfold/interfold/blob/4ace535c1ff4d7897ec958a943cb45c55dc298a7/examples/CRISP/packages/crisp-contracts/contracts/CRISPProgram.sol)
- [Ballot constraints](https://github.com/theinterfold/interfold/blob/4ace535c1ff4d7897ec958a943cb45c55dc298a7/examples/CRISP/circuits/lib/src/utils.nr)
