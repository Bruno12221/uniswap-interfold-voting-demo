// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;
import { T06Fixture } from "./T06Fixture.sol";
interface IT07Honk { function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool); }
/// @dev Local browser admission fixture only. Other inherited verifier and state fixtures remain mutable.
contract T07Fixture is T06Fixture {
    IT07Honk public immutable ballotVerifier;
    mapping(bytes32 => bool) private admitted;
    constructor(address verifier) { ballotVerifier = IT07Honk(verifier); }
    function isInputCommitted(uint256 id, bytes32 hash, bytes32 commitment, address slot, uint40 parent) external view returns (bool) {
        return admitted[this.inputId(id, hash, commitment, slot, parent)];
    }
    function publishBallot(uint256 id, bytes calldata encoded) external {
        (bytes memory proof, address slot, bytes32 commitment, bytes32 hash, uint40 parent, bytes memory ciphertext) =
            abi.decode(encoded, (bytes, address, bytes32, bytes32, uint40, bytes));
        require(keccak256(ciphertext) == hash && ciphertext.length > 0, "fixture ciphertext hash");
        _admit(id, proof, slot, commitment, hash, parent);
    }
    function publishInput(uint256 id, bytes calldata encoded) external {
        (bytes memory proof, address slot, bytes32 commitment, bytes32 hash, uint40 parent, uint64 expiry, bytes memory attestation) =
            abi.decode(encoded, (bytes, address, bytes32, bytes32, uint40, uint64, bytes));
        // Availability signature cryptography is deliberately a fixture; the seven-field wire format is real.
        require(block.timestamp < expiry && attestation.length == 65, "fixture attestation shape");
        _admit(id, proof, slot, commitment, hash, parent);
    }
    function _admit(uint256 id, bytes memory proof, address slot, bytes32 commitment, bytes32 hash, uint40 parent) internal {
        (uint256 census,, uint256 options,,, uint40 count) = this.getRoundData(id);
        require(parent <= count, "fixture parent bound");
        bytes32 previous = parent == 0 ? bytes32(0) : this.inputCommitmentOf(id, slot, parent - 1);
        require(parent == 0 || previous != bytes32(0), "fixture parent slot");
        bytes32 digest = this.ballotDigest(id, slot, commitment);
        bytes32[] memory inputs = new bytes32[](9);
        inputs[0] = previous; inputs[1] = bytes32(uint256(digest) >> 128);
        inputs[2] = bytes32(uint256(uint128(uint256(digest)))); inputs[3] = bytes32(uint256(uint160(slot)));
        inputs[4] = bytes32(census); inputs[5] = bytes32(uint256(parent == 0 ? 1 : 0));
        inputs[6] = bytes32(options); inputs[7] = commitment; inputs[8] = e3.committeePublicKey;
        require(ballotVerifier.verify(proof, inputs), "fixture invalid ballot proof");
        this.commitInput(id, slot, commitment, hash, parent);
        admitted[this.inputId(id, hash, commitment, slot, parent)] = true;
    }
}
