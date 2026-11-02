# Historical voting rules

Recorded: 19 October 2026. This is a read-only reference for an experimental adapter. It does not create a new official poll or authorize voting on behalf of anyone.

## Selected proposal

| Field | Frozen value |
| --- | --- |
| Title | Launching Uniswap v3 on Ronin with co-incentives |
| Space | `uniswapgovernance.eth` |
| Proposal ID | `0xfc6edc8b64e1fa8eef46d187557969b14ca24ac58b8b6d6b302ea27a2213849d` |
| Network | Ethereum mainnet, chain ID `1` |
| Snapshot block | `23,265,853` (`0x163023d`) |
| Block hash | `0xf8812eeef257de7fb4e834e10a49c94a8738524cf3cce6ca54e4fd2efe119b0e` |
| Opens | 1 September 2025, 14:00 UTC; Unix `1756735200` |
| Closes | 6 September 2025, 14:00 UTC; Unix `1757167200` |
| Duration | 432,000 seconds, or five days |
| State | Closed, scores final |
| Voting type | `single-choice` |
| Choice 1 | `Deploy $500k in UNI Incentives` |
| Choice 2 | `Do not deploy incentives` |
| Status quo | Choice 2: no incentive allocation under this proposal |
| Abstain choice | None; do not add one to a faithful reproduction |
| Proposal quorum field | `10,000,000` UNI |
| Strategy | One `uni` strategy on network `1`, decimals `18` |
| UNI address | `0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984` |
| Proposal IPFS reference | `bafkreigoyib5dfjramb2jfpb3zgt7txtjkvm6hdn2kv5aosjgz45cjmt2q` |

This poll was selected because it is a completed, two-choice preliminary vote with an explicit no-change option. There is no ranked choice, allocation voting or added abstention to translate.

The canonical space was verified through the older governance-process proposal linked by the official forum, which resolves to `uniswapgovernance.eth`. The selected Ronin forum thread also links to this Snapshot poll. A similar space name alone was not used as evidence.

## Passage rule and reference result

The community process describes a winning majority and at least 10 million affirmative UNI votes to advance to the onchain stage. For this binary poll, the reference policy is choice 1 greater than choice 2, and choice 1 at least `10,000,000` UNI. Equality between choices does not establish a majority. A lack of votes is not a pass.

The proposal API's quorum field is recorded separately. It is not evidence that total turnout alone replaces the process's affirmative-vote requirement. The later onchain governor has different requirements and is outside this adapter.

The API reports approximately 11.544 million UNI for choice 1 and 8.906 million for choice 2. A later update in the source forum says the Snapshot vote passed. The API's displayed decimal totals are saved as strings in the evidence record; they are not an exact integer tally or a fixture of private ballots.

## What the strategy actually reads

The strategy is `uni`, version `0.1.1`, not `erc20-balance-of` and not a generic `ERC20Votes` strategy.

For each address it calls **`getCurrentVotes(address)` on UNI at the proposal's historical block tag**. The result is a `uint96` count of delegated voting units. It then formats those units with 18 decimals and converts the decimal string to a JavaScript floating-point number.

Consequences for the later adapter:

- An undelegated UNI balance is not automatically voting power.
- Delegated units count for the recipient delegate, not again for the delegator's wallet balance.
- Self-delegation counts according to the checkpoint at the selected block.
- Do not add wallet balances or another delegation registry on top of this one strategy.
- The inspected strategy uses its own network-to-token address mapping. Preserve the actual network/address behaviour rather than treating arbitrary strategy parameters as interchangeable.
- A positive historical delegated weight is the scoring basis. Eligibility and wallet authorization are separate checks in the new application.

The latest change to the strategy file before the poll was commit `50b3c96bae6f980248fde9d7fb198e2ca9492166`, dated 13 October 2021. The file at that revision is byte-for-byte identical to the file at current inspected revision `91abd258f10b4e881375890647bc0b5c58bd1cfb`. Its SHA-256 is `95f7d36e652cdf7b254d0f3e693a0c91638cab6131eb9554095eeaeec251ee38`.

This pins the inspected strategy implementation. It does not establish the full historical Snapshot server build, runtime or scoring-service dependency lock.

## Native UNI and CRISP differ

Native UNI provides `getCurrentVotes(address)` and `getPriorVotes(address,uint256)`. Its historical checkpoints are block-number based. It does not implement CRISP's expected `getPastVotes` and `getPastTotalSupply` interfaces.

CRISP's custom-weight setup also obtains a previous token timepoint and divides weights to keep totals below the plaintext modulus. Pointing it directly at UNI will not preserve this historical poll's block, interface or precision.

Use a reproducible frozen census as the candidate integration boundary. T04 must derive it from the selected source rule, bind the exact block and strategy configuration, and document the root publisher's authority. No census has been constructed during T01.

UNI's native `getPriorVotes(address, snapshotBlock)` at a later finalized block is a possible way to read retained historical checkpoints without an archive-state call. T04 must validate its equivalence to this strategy and handle source-block identity. Do not silently use present-day `getCurrentVotes`.

## T02 precision finding

The chain's delegated weights are exact integers. Snapshot's inspected strategy converts them to floating-point scores; rounding and order of addition can affect displayed values.

T02 distinguishes preserving exact economic voting units from reproducing historical display scores. Its [feasibility report](FEASIBILITY.md) demonstrates synthetic majority and threshold comparisons that differ after floating-point conversion. Do not claim that both targets are identical. Do not recover raw weights by multiplying rounded API scores by `10^18`.

The research target retains raw integer units and `FOR > AGAINST && FOR >= 10^25`. No live compatibility policy, rounding, multi-limb circuit or census interface is approved by this record. The real-UNI milestone remains blocked; no changed verdict for this historical poll is asserted.

## How to retrieve the configuration again

The [evidence record](reference/t01-evidence.json) contains the exact public GraphQL query. Send it to `https://hub.snapshot.org/graphql` with a GET query parameter. The POST attempt returned HTTP 403 during research; the unauthenticated GET returned the configuration successfully.

From this repository's root, this standard-library command retrieves it again:

```sh
python3 - <<'PY'
import json
import urllib.parse
import urllib.request

with open('docs/reference/t01-evidence.json') as source:
    evidence = json.load(source)
query = urllib.parse.urlencode({'query': evidence['snapshotApi']['query']})
request = urllib.request.Request(
    evidence['snapshotApi']['endpoint'] + '?' + query,
    headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'},
)
with urllib.request.urlopen(request, timeout=30) as response:
    print(json.dumps(json.load(response), indent=2))
PY
```

The selected proposal's stored strategies are the reference; today's space settings are only a comparison. Check the source block hash through `cast block 23265853 --json --rpc-url PUBLIC_RPC`.

The public RPC used during T01 returned the block header but denied historical contract-state calls without archive access. Direct archived strategy parity therefore remains untested. Archive access or a validated native-checkpoint alternative is a T04 dependency.

T04 resolved access for its five public reference cases through Snapshot's public RPC. Historical `getCurrentVotes`, later `getPriorVotes`, an independent checkpoint search and Snapshot's per-address score agree for those cases. See [the public reference evidence](reference/t04-evidence.json). This is not a full historical tally reconstruction or a real-UNI compatibility decision.

## Sources

- [Selected Snapshot poll](https://snapshot.box/#/s:uniswapgovernance.eth/proposal/0xfc6edc8b64e1fa8eef46d187557969b14ca24ac58b8b6d6b302ea27a2213849d)
- [Source forum thread and later result update](https://gov.uniswap.org/t/rfc-deploying-uniswap-v3-on-ronin-with-co-incentives/25810)
- [Community governance process](https://gov.uniswap.org/t/community-governance-process-update-jan-2023/19976)
- [Historical strategy source](https://github.com/snapshot-labs/snapshot-strategies/blob/50b3c96bae6f980248fde9d7fb198e2ca9492166/src/strategies/uni/index.ts)
- [Inspected native UNI source](https://github.com/Uniswap/governance/blob/eabd8c71ad01f61fb54ed6945162021ee419998e/contracts/Uni.sol)
