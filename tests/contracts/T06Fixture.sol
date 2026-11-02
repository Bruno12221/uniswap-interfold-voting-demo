// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { T05Fixture } from "./T05Fixture.sol";
import { OpenVmReceiptVerifier } from "@interfold/contracts/contracts/verifiers/OpenVmReceiptVerifier.sol";
import { IOpenVmReceiptVerifier } from "@interfold/contracts/contracts/interfaces/IOpenVmReceiptVerifier.sol";
import { OpenVmComputeProof } from "@interfold/contracts/contracts/lib/OpenVmComputeProof.sol";
import { CommitteeHashLib } from "@interfold/contracts/contracts/lib/CommitteeHashLib.sol";
import { IDataAvailabilityVerifier } from "@interfold/contracts/contracts/interfaces/IDataAvailabilityVerifier.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { IPkVerifier } from "@interfold/contracts/contracts/interfaces/IPkVerifier.sol";
import { IDecryptionVerifier } from "@interfold/contracts/contracts/interfaces/IDecryptionVerifier.sol";

/// @dev All contracts in this file are mutable orchestration fixtures, not secure verifiers.
contract T06Halo2Fixture {
    bytes32 public journalDigest;
    bytes32 public proofHash;
    function expect(bytes32 digest, bytes32 hash) external { journalDigest = digest; proofHash = hash; }
    function verify(bytes calldata values, bytes calldata proof, bytes32, bytes32) external view {
        require(keccak256(values) == keccak256(abi.encodePacked(journalDigest)) && keccak256(proof) == proofHash, "fixture proof mismatch");
    }
}

contract T06CommitteeFixture {
    address[] private nodes;
    constructor(address[] memory members) { nodes = members; }
    function getCommitteeNodes(uint256) external view returns (address[] memory) { return nodes; }
    function getCommitteeHash(uint256) external view returns (bytes32) { return CommitteeHashLib.hash(nodes); }
    function rootAt(uint256) external pure returns (uint256) { return 777; }
}

contract T06ProofFixture {
    address public immutable ciphernodeRegistry;
    bytes32 public expectedCall;
    constructor(address registry) { ciphernodeRegistry = registry; }
    function expect(bytes32 value) external { expectedCall = value; }
    function verify(uint256 id, uint256 root, address[] calldata nodes, bytes32 key, bytes32 committee, bytes calldata proof) external view returns (bool) {
        require(keccak256(abi.encode(id, root, nodes, key, committee, proof)) == expectedCall, "fixture key proof mismatch");
        return true;
    }
    function verify(uint256 id, bytes32 domain, bytes32 plaintext, bytes32 committee, bytes32 ciphertext, bytes calldata proof) external view returns (bool) {
        require(keccak256(abi.encode(id, domain, plaintext, committee, ciphertext, proof)) == expectedCall, "fixture decryption proof mismatch");
        return true;
    }
}

contract T06AvailabilityFixture is IDataAvailabilityVerifier {
    function verifyDataAvailability(bytes32 expectedHash, bytes calldata proof) external pure returns (DataReference memory receipt) {
        receipt = abi.decode(proof, (DataReference));
        require(receipt.contentHash == expectedHash && expectedHash != bytes32(0), "fixture availability mismatch");
    }
}

contract T06Fixture is T05Fixture {
    address public interfold;
    IOpenVmReceiptVerifier public openVmVerifier;
    bytes32 public imageId;
    IDataAvailabilityVerifier public dataAvailabilityVerifier;
    T06CommitteeFixture public committee;
    T06ProofFixture public decryption;
    uint256 private commitmentDeadline;
    uint256 private computeDeadline;
    uint256 private decryptionDeadline;
    mapping(bytes32 => bool) private committed;
    mapping(bytes32 => bool) private published;
    mapping(bytes32 => uint40) private indices;

    event InputCommitted(uint256 indexed e3Id, bytes32 indexed inputId, address indexed slotAddress,
        bytes32 encryptedVoteCommitment, bytes32 encryptedVoteHash, uint40 parentIndexPlusOne, uint40 index);
    event InputPublished(uint256 indexed e3Id, address indexed slotAddress, bytes32 encryptedVoteCommitment,
        bytes32 encryptedVoteHash, uint32 availabilityBlock, uint128 availabilityLeafIndex, uint256 index, uint40 parentIndexPlusOne);
    event CiphertextOutputReferencePublished(uint256 indexed e3Id, bytes32 contentHash, bytes32 ciphertextCommitment, uint32 availabilityBlock, uint128 availabilityLeafIndex);
    event PlaintextOutputPublished(uint256 indexed e3Id, bytes plaintextOutput, bytes proof);

    function configureCoordinator(address receipt, address availability, address registry, address pk, address decryptor, uint256 cutoff, uint256 computeEnd) external {
        interfold = address(this); openVmVerifier = IOpenVmReceiptVerifier(receipt);
        imageId = openVmVerifier.imageId(); dataAvailabilityVerifier = IDataAvailabilityVerifier(availability);
        committee = T06CommitteeFixture(registry); decryption = T06ProofFixture(decryptor);
        e3.pkVerifier = IPkVerifier(pk); e3.decryptionVerifier = IDecryptionVerifier(decryptor);
        e3.encryptionSchemeId = keccak256("fhe.rs:BFV"); e3.requestBlock = block.timestamp;
        commitmentDeadline = cutoff; computeDeadline = computeEnd;
    }
    function inputCommitmentDeadline(uint256) external view override returns (uint256) { return commitmentDeadline; }
    function getDeadlines(uint256) external view returns (IInterfold.E3Deadlines memory) {
        return IInterfold.E3Deadlines(0, computeDeadline, decryptionDeadline);
    }
    function inputId(uint256 id, bytes32 hash, bytes32 commitment, address slot, uint40 parent) public view returns (bytes32) {
        return keccak256(abi.encode("CRISP_INPUT_V1", address(this), id, hash, commitment, slot, parent));
    }
    function commitInput(uint256 id, address slot, bytes32 commitment, bytes32 hash, uint40 parent) external {
        require(block.timestamp < commitmentDeadline && block.timestamp >= e3.inputWindow[0], "fixture commitment deadline");
        bytes32 identifier = inputId(id, hash, commitment, slot, parent); require(!committed[identifier], "fixture replay");
        (,,,,, uint40 count) = this.getRoundData(id);
        uint256 leaf = uint256(sha256(abi.encodePacked(hash, commitment, slot, parent))) % 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        this.append(leaf, slot, commitment); this.setPending(this.pendingInputCount(id) + 1);
        committed[identifier] = true; indices[identifier] = count;
        emit InputCommitted(id, identifier, slot, commitment, hash, parent, count);
    }
    function finalizeInput(uint256 id, address slot, bytes32 commitment, bytes32 hash, uint40 parent, bytes calldata proof) external {
        require(block.timestamp <= computeDeadline, "fixture availability deadline");
        bytes32 identifier = inputId(id, hash, commitment, slot, parent);
        require(committed[identifier] && !published[identifier], "fixture input unavailable");
        IDataAvailabilityVerifier.DataReference memory receipt = dataAvailabilityVerifier.verifyDataAvailability(hash, proof);
        published[identifier] = true; this.setPending(this.pendingInputCount(id) - 1);
        emit InputPublished(id, slot, commitment, hash, receipt.blockNumber, receipt.leafIndex, indices[identifier], parent);
    }
    function verify(uint256 id, bytes32 hash, bytes32 commitment, bytes memory proof) public view returns (bool) {
        (, bytes32 params,,,,) = this.getRoundData(id);
        (,,,, uint256 root,) = this.getRoundData(id);
        OpenVmComputeProof.Proof memory p = OpenVmComputeProof.decode(proof);
        require(this.pendingInputCount(id) == 0 && p.paramsHash == params && p.inputRoot == bytes32(root), "fixture compute context");
        bytes memory journal = OpenVmComputeProof.journal(bytes32(block.chainid), bytes32(uint256(uint160(address(this)))), bytes32(id),
            e3.encryptionSchemeId, e3.committeePublicKey, hash, commitment, params, bytes32(root));
        openVmVerifier.verify(p.seal, imageId, sha256(journal)); return true;
    }
    function publishCiphertextOutput(uint256 id, bytes calldata encoded) external {
        require(block.timestamp >= e3.inputWindow[1] && block.timestamp <= computeDeadline && this.getE3Stage(id) == IInterfold.E3Stage.KeyPublished, "fixture compute deadline");
        IInterfold.CiphertextOutputReference memory output = abi.decode(encoded, (IInterfold.CiphertextOutputReference));
        IDataAvailabilityVerifier.DataReference memory receipt = dataAvailabilityVerifier.verifyDataAvailability(output.contentHash, output.availabilityProof);
        require(verify(id, output.contentHash, output.ciphertextCommitment, output.computeProof));
        e3.ciphertextOutput = output.contentHash; e3.ciphertextCommitment = output.ciphertextCommitment;
        this.setStage(IInterfold.E3Stage.CiphertextReady); decryptionDeadline = block.timestamp + 600;
        emit CiphertextOutputReferencePublished(id, output.contentHash, output.ciphertextCommitment, receipt.blockNumber, receipt.leafIndex);
    }
    function publishPlaintextOutput(uint256 id, bytes calldata plaintext, bytes calldata proof) external returns (bool) {
        require(this.getE3Stage(id) == IInterfold.E3Stage.CiphertextReady && block.timestamp <= decryptionDeadline, "fixture decryption deadline");
        bytes32 committeeHash = committee.getCommitteeHash(id);
        bytes32 domain = keccak256(abi.encode(block.chainid, address(this), id, committeeHash, e3.ciphertextOutput, e3.committeePublicKey));
        require(decryption.verify(id, domain, keccak256(plaintext), committeeHash, e3.ciphertextCommitment, proof));
        this.setResult(plaintext); emit PlaintextOutputPublished(id, plaintext, proof); return true;
    }
}
