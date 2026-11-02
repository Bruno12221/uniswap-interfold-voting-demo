// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { IE3Program } from "@interfold/contracts/contracts/interfaces/IE3Program.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { InternalLazyIMT, LazyIMTData } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";

/// @dev Mutable protocol-view fixture only. This is not an Interfold implementation or verifier.
contract T05Fixture is EIP712 {
    using InternalLazyIMT for LazyIMTData;
    E3 internal e3;
    LazyIMTData private tree;
    uint256 private censusRoot;
    bytes32 private paramsHash;
    uint256 private options;
    uint40 private count;
    uint40 private pending;
    IInterfold.E3Stage private stage;
    mapping(address => mapping(uint40 => bytes32)) private commitments;

    constructor() EIP712("CRISP", "1") { tree._init(20); }

    function configure(uint256 root, bytes32 params, uint256 numOptions, bytes32 key, uint8 paramSet, uint256 start, uint256 end) external {
        censusRoot = root; paramsHash = params; options = numOptions;
        e3.e3Program = IE3Program(address(this));
        e3.committeePublicKey = key; e3.paramSet = paramSet;
        e3.inputWindow = [start, end]; e3.requester = msg.sender;
        e3.customParams = abi.encode(address(0), uint256(1), numOptions, uint8(0), uint256(1), uint256(1), uint256(0));
        stage = IInterfold.E3Stage.KeyPublished;
    }

    function getE3(uint256) external view returns (E3 memory) { return e3; }
    function getE3Stage(uint256) external view returns (IInterfold.E3Stage) { return stage; }
    function getRoundData(uint256) external view returns (uint256, bytes32, uint256, uint8, uint256, uint40) {
        return (censusRoot, paramsHash, options, 0, tree._root(), count);
    }
    function pendingInputCount(uint256) external view returns (uint40) { return pending; }
    function inputCommitmentDeadline(uint256) external view virtual returns (uint256) { return e3.inputWindow[1] - 60; }
    function inputCommitmentOf(uint256, address slot, uint40 index) external view returns (bytes32) { return commitments[slot][index]; }
    function ballotDigest(uint256 e3Id, address slot, bytes32 commitment) external view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(
            keccak256("Ballot(uint256 e3Id,address slot,bytes32 ciphertextCommitment)"), e3Id, slot, commitment)));
    }
    function append(uint256 leaf, address slot, bytes32 commitment) external {
        require(count == tree.numberOfLeaves, "fixture count mismatch");
        commitments[slot][count] = commitment;
        tree._insert(leaf); count++;
    }
    function setCount(uint40 value) external { count = value; }
    function setPending(uint40 value) external { pending = value; }
    function setStage(IInterfold.E3Stage value) external { stage = value; }
    function setResult(bytes calldata value) external { e3.plaintextOutput = value; stage = IInterfold.E3Stage.Complete; }
}

/// @dev Signature transport fixture; not a production wallet.
contract T05ContractWallet {
    address public immutable owner;
    constructor(address _owner) { require(_owner != address(0)); owner = _owner; }
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (signature.length != 65) return 0xffffffff;
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := calldataload(signature.offset) s := calldataload(add(signature.offset, 32)) v := byte(0, calldataload(add(signature.offset, 64))) }
        return ecrecover(hash, v, r, s) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
