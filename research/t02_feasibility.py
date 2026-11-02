#!/usr/bin/env python3
"""Synthetic T02 arithmetic and inference exercises; no encryption or real ballots.

Uses Python's standard library and an existing Node runtime. Large raw integers
are saved as decimal strings so JSON consumers cannot silently round them.
"""

import argparse
import itertools
import json
from pathlib import Path
import random
import subprocess


REVISION = "4ace535c1ff4d7897ec958a943cb45c55dc298a7"
MODULUS = 17_000_000
MAX_INPUTS = 100_000
BASE = 128
LIMBS = 14
MAX_WEIGHT = (1 << 96) - 1
UNIT = 10**18


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digits(weight):
    if not 0 <= weight <= MAX_WEIGHT:
        raise ValueError("weight outside uint96")
    return [(weight >> (7 * index)) & 127 for index in range(LIMBS)]


def reconstruct(coefficients):
    return sum(value * BASE**index for index, value in enumerate(coefficients))


def choice_coefficients(weights, choices):
    return [
        [sum(digits(w)[j] for w, c in zip(weights, choices) if c == option)
         for j in range(LIMBS)]
        for option in (0, 1)
    ]


def candidates(weights, for_total, known=None, coefficients=None):
    """Enumerate full-weight binary assignments for a known contributing roster.

    1 = FOR; 0 = AGAINST. This models the intended single-choice rule, not
    current CRISP's permissive weighted ballots. Both published totals sum to
    the entire known roster weight. No unseen voter or partial ballot assumed.
    """
    known = known or {}
    result = []
    for assignment in itertools.product((0, 1), repeat=len(weights)):
        if any(assignment[i] != choice for i, choice in known.items()):
            continue
        if sum(w * c for w, c in zip(weights, assignment)) != for_total:
            continue
        if coefficients is not None:
            # choice_coefficients uses 0 then 1, unlike the human FOR/AGAINST order.
            if choice_coefficients(weights, assignment) != coefficients:
                continue
        result.append(assignment)
    return result


def inference_case(name, weights, for_total, expected_count, expected_forced, known=None):
    known = known or {}
    matches = candidates(weights, for_total, known)
    forced = {
        str(i): "FOR" if matches[0][i] else "AGAINST"
        for i in range(len(weights))
        if i not in known and matches and len({m[i] for m in matches}) == 1
    }
    require(len(matches) == expected_count, name + ": wrong candidate count")
    require(forced == expected_forced, name + ": wrong inference")
    return {
        "name": name, "syntheticWeights": weights,
        "forTotal": for_total, "againstTotal": sum(weights) - for_total,
        "knownChoicesByIndex": {str(i): "FOR" if c else "AGAINST" for i, c in known.items()},
        "compatibleAssignments": len(matches), "newlyForcedChoicesByIndex": forced,
    }


def arithmetic():
    boundary = [0, 1, 127, 128, (1 << 95), MAX_WEIGHT]
    rng = random.Random(20261019)
    samples = boundary + [rng.randrange(MAX_WEIGHT + 1) for _ in range(1000)]
    for weight in samples:
        encoded = digits(weight)
        require(reconstruct(encoded) == weight, "individual reconstruction")
        require(all(0 <= d < BASE for d in encoded), "digit range")
        require(encoded[-1] <= 31, "top digit range")
    for invalid in (-1, 1 << 96):
        try:
            digits(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid weight accepted")
    for _ in range(200):
        weights = [rng.randrange(MAX_WEIGHT + 1) for _ in range(rng.randrange(101))]
        summed = [sum(digits(w)[j] for w in weights) for j in range(LIMBS)]
        require(reconstruct(summed) == sum(weights), "group reconstruction with carries")
    bounds = [MAX_INPUTS * 127] * 13 + [MAX_INPUTS * 31]
    require(all(c < MODULUS for c in bounds), "coefficient wraparound")
    require(reconstruct(bounds) == MAX_INPUTS * MAX_WEIGHT, "maximum group reconstruction")
    require(MAX_INPUTS * 255 >= MODULUS, "base 256 must fail at proposed bound")
    divisor = 10**27 // MODULUS + 1
    return {
        "plaintextModulus": MODULUS, "authenticatedCoefficients": 50,
        "coefficientStorageBits": 64, "maxAdmittedInputs": MAX_INPUTS,
        "rawWeightBits": 96, "maxRawWeight": str(MAX_WEIGHT),
        "candidateBase": BASE, "limbsPerChoice": LIMBS,
        "maxEffectiveSlotsAssumed": MAX_INPUTS, "summedCoefficientBounds": bounds,
        "choiceCapacity": [{"choices": c, "coefficientsNeeded": c * LIMBS,
                            "fitsOutputOnly": c * LIMBS <= 50} for c in (2, 3, 4)],
        "maxRawTotal": str(MAX_INPUTS * MAX_WEIGHT),
        "maxRawTotalBits": (MAX_INPUTS * MAX_WEIGHT).bit_length(),
        "base256WorstCoefficient": MAX_INPUTS * 255,
        "oneUniRaw": str(UNIT), "oneUniModuloT": UNIT % MODULUS,
        "affirmativeThresholdRaw": str(10_000_000 * UNIT),
        "illustrativeSupplyRaw": str(10**27),
        "illustrativeMinimumDivisorRaw": str(divisor),
        "individualRoundTrips": len(samples), "groupRoundTrips": 200,
        "rejectedWeights": ["-1", str(1 << 96)],
        "status": "integer model only; not a circuit, FHE test or approved private encoding",
    }


def limb_leakage():
    weights = [1, 127, 128]
    # A: FOR the first two; B: FOR the last one. Both scalar totals = 128, 128.
    assignments = [(1, 1, 0), (0, 0, 1)]
    outputs = [choice_coefficients(weights, assignment) for assignment in assignments]
    scalar = candidates(weights, 128)
    counts = [len(candidates(weights, 128, coefficients=o)) for o in outputs]
    require(len(scalar) == 2 and counts == [1, 1], "extra limb disclosure")
    require(all([reconstruct(c) for c in o] == [128, 128] for o in outputs), "same totals")
    return {
        "syntheticWeights": weights, "forTotal": 128, "againstTotal": 128,
        "scalarCompatibleAssignments": len(scalar),
        "examples": [{"choicesByIndex": list(a), "forCoefficients": o[1],
                      "againstCoefficients": o[0], "coefficientCompatibleAssignments": count}
                     for a, o, count in zip(assignments, outputs, counts)],
        "finding": "public uncarried digit sums distinguish otherwise identical scalar totals",
    }


def decimal_units(raw):
    return f"{raw // UNIT}.{raw % UNIT:018d}"


def precision():
    examples = [
        ("strict_majority", 1_000_000 * UNIT + 1, 1_000_000 * UNIT),
        ("affirmative_threshold", 10_000_000 * UNIT - 1, 10_000_000 * UNIT),
    ]
    payload = [{"name": name, "left": decimal_units(a), "right": decimal_units(b)}
               for name, a, b in examples]
    javascript = """let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  const result = JSON.parse(input).map(row => {
    const a = Number.parseFloat(row.left), b = Number.parseFloat(row.right);
    return {name: row.name, leftParsed: String(a), rightParsed: String(b),
            equal: a === b, leftGreater: a > b, leftAtLeast: a >= b};
  });
  process.stdout.write(JSON.stringify(result));
});
"""
    process = subprocess.run(["node", "-e", javascript], input=json.dumps(payload),
                             text=True, capture_output=True, check=True)
    parsed = json.loads(process.stdout)
    require(all(row["equal"] for row in parsed), "expected floating-point collision")
    require(not parsed[0]["leftGreater"] and parsed[1]["leftAtLeast"], "boundary outcomes")
    return [dict(row, leftRaw=str(a), rightRaw=str(b), leftExact=decimal_units(a),
                 rightExact=decimal_units(b), exactLeftGreater=a > b, exactLeftAtLeast=a >= b)
            for row, (_, a, b) in zip(parsed, examples)]


def report():
    cases = [
        inference_case("equal_weight_control", [1] * 8, 4, 70, {}),
        inference_case("powers_of_two", [1, 2, 4, 8, 16, 32, 64, 128], 37, 1,
                       {str(i): "FOR" if i in (0, 2, 5) else "AGAINST" for i in range(8)}),
        inference_case("distinct_weights_not_always_unique", [1, 2, 3], 3, 2, {}),
        inference_case("dominant_voter", [100] + [1] * 11, 105, 462, {"0": "FOR"}),
        inference_case("one_voter", [7], 7, 1, {"0": "FOR"}),
        inference_case("known_other_ballots", [1] * 8, 4, 1, {"7": "AGAINST"},
                       {i: int(i < 4) for i in range(7)}),
        inference_case("unanimous", [1] * 8, 8, 1, {str(i): "FOR" for i in range(8)}),
    ]
    return {
        "schemaVersion": 1, "task": "T02", "sourceRevision": REVISION,
        "fixtureType": "entirely synthetic; no real voter addresses or ballots",
        "inferenceModel": "known contributing roster, full-weight single-choice binary ballots; both totals public",
        "arithmetic": arithmetic(), "inferenceCases": cases,
        "additionalLimbLeakage": limb_leakage(), "javascriptPrecision": precision(),
        "decisions": {"syntheticMechanics": "proceed only when next task is authorized",
                      "realUniPrivatePilot": "no-go under this design"},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).resolve().parents[1] / "docs/reference/t02-evidence.json")
    parser.add_argument("--check", action="store_true", help="compare without changing saved evidence")
    args = parser.parse_args()
    content = json.dumps(report(), indent=2) + "\n"
    if args.check:
        require(args.output.read_text() == content, "saved evidence differs; review before regenerating")
        print("T02 checks passed; saved evidence matches.")
    else:
        args.output.write_text(content)
        print("T02 checks passed; synthetic evidence written.")


if __name__ == "__main__":
    main()
