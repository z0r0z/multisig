// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IMultisig} from "./interfaces/IMultisig.sol";

/// @dev Executor module for queued transaction management. Cancel requires
/// threshold approvals (symmetric with signing). Fast-forward requires
/// all owners (unanimous) since it bypasses the timelock protection.
/// Fast-forward is opt-in — the multisig must call enableForward(true).
/// Singleton — one deployment serves all multisigs.
contract CancelTx {
    event Cancelled(address indexed multisig, bytes32 indexed hash);
    event Forwarded(address indexed multisig, bytes32 indexed id);
    event ForwardEnabled(address indexed multisig, bool enabled);
    event Voted(address indexed multisig, bytes32 indexed id, address indexed owner);

    error Unauthorized();

    mapping(address multisig => mapping(bytes32 hash => mapping(address owner => bool))) public cancelVoted;
    mapping(address multisig => mapping(bytes32 hash => uint256)) public cancelVotes;

    mapping(address multisig => bool) public forwardEnabled;
    mapping(address multisig => mapping(bytes32 id => mapping(address owner => bool))) public forwardVoted;
    mapping(address multisig => mapping(bytes32 id => uint256)) public forwardVotes;

    constructor() payable {}

    function enableForward(bool enabled) public {
        forwardEnabled[msg.sender] = enabled;
        emit ForwardEnabled(msg.sender, enabled);
    }

    /// @dev Owners approve cancellation of a queued tx. Auto-cancels at threshold.
    function cancel(address multisig, bytes32 hash) public {
        require(IMultisig(multisig).isOwner(msg.sender), Unauthorized());
        require(!cancelVoted[multisig][hash][msg.sender], Unauthorized());
        cancelVoted[multisig][hash][msg.sender] = true;
        emit Voted(multisig, hash, msg.sender);
        if (++cancelVotes[multisig][hash] >= IMultisig(multisig).threshold()) {
            IMultisig(multisig).cancelQueued(hash);
            emit Cancelled(multisig, hash);
        }
    }

    /// @dev Owners approve immediate execution, bypassing timelock. Auto-executes when all owners have approved.
    function forward(address multisig, address target, uint256 value, bytes calldata data) public {
        require(forwardEnabled[multisig], Unauthorized());
        require(IMultisig(multisig).isOwner(msg.sender), Unauthorized());
        bytes32 id = keccak256(abi.encode(target, value, data));
        require(!forwardVoted[multisig][id][msg.sender], Unauthorized());
        forwardVoted[multisig][id][msg.sender] = true;
        emit Voted(multisig, id, msg.sender);
        if (++forwardVotes[multisig][id] >= IMultisig(multisig).ownerCount()) {
            IMultisig(multisig).execute(target, value, data, "");
            emit Forwarded(multisig, id);
        }
    }
}
