// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";

interface ICrispRoundView {
    function getRoundData(uint256 e3Id) external view returns (
        uint256 root, bytes32 paramsHash, uint256 numOptions,
        uint8 creditMode, uint256 inputRoot, uint40 inputCount
    );
}

/// @notice Local synthetic context registry. It does not verify tallies or custody assets.
contract FrozenRoundRegistry {
    address public immutable publisher;
    mapping(bytes32 => bytes32) private manifests;

    struct FreezeRequest {
        address interfold;
        address program;
        uint256 e3Id;
        bytes32 manifestHash;
        uint256 censusRoot;
        bytes32 paramsHash;
        bytes32 committeeKey;
        uint256 numOptions;
    }

    error LocalChainOnly();
    error OnlyPublisher();
    error AlreadyFrozen();
    error RoundHasInputs();
    error InvalidProfile();
    error RoundMismatch();

    event RoundFrozen(address indexed interfold, address indexed program, uint256 indexed e3Id, bytes32 manifestHash);

    constructor(address _publisher) {
        if (block.chainid != 31337) revert LocalChainOnly();
        if (_publisher == address(0)) revert InvalidProfile();
        publisher = _publisher;
    }

    function getManifestHash(address interfold, address program, uint256 e3Id) external view returns (bytes32) {
        return manifests[keccak256(abi.encode(interfold, program, e3Id))];
    }

    function freeze(FreezeRequest calldata request) external {
        if (msg.sender != publisher) revert OnlyPublisher();
        bytes32 slot = keccak256(abi.encode(request.interfold, request.program, request.e3Id));
        if (manifests[slot] != bytes32(0)) revert AlreadyFrozen();
        if (request.manifestHash == bytes32(0) || request.censusRoot == 0 || request.committeeKey == bytes32(0) ||
            request.paramsHash == bytes32(0) || request.numOptions < 2 || request.numOptions > 3) revert InvalidProfile();

        IInterfold protocol = IInterfold(request.interfold);
        E3 memory e3 = protocol.getE3(request.e3Id);
        if (protocol.getE3Stage(request.e3Id) != IInterfold.E3Stage.KeyPublished ||
            address(e3.e3Program) != request.program || e3.committeePublicKey != request.committeeKey ||
            block.timestamp >= e3.inputWindow[1] || (e3.paramSet != 0 && e3.paramSet != 2)) revert RoundMismatch();

        (, , uint256 options, uint8 mode, uint256 credits, uint256 censusMode, ) =
            abi.decode(e3.customParams, (address, uint256, uint256, uint8, uint256, uint256, uint256));
        if (options != request.numOptions || mode != 0 || credits != 1 || censusMode > 1) revert InvalidProfile();

        (uint256 root, bytes32 paramsHash, uint256 numOptions, uint8 creditMode, , uint40 count) =
            ICrispRoundView(request.program).getRoundData(request.e3Id);
        if (count != 0) revert RoundHasInputs();
        if (root != request.censusRoot || paramsHash != request.paramsHash ||
            numOptions != request.numOptions || creditMode != 0) revert RoundMismatch();

        manifests[slot] = request.manifestHash;
        emit RoundFrozen(request.interfold, request.program, request.e3Id, request.manifestHash);
    }
}
