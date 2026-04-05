// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IMultisig} from "./interfaces/IMultisig.sol";

/// @dev Executor module for timelock management via off-chain signatures.
/// Uses the multisig's own EIP-712 Execute typehash — the same signatures
/// collected for normal execute work here. The UI routes based on count:
///   - All owners signed -> forward() for immediate execution (opt-in)
///   - Threshold signed + cancel selector -> forward() for immediate cancel
///   - Threshold signed otherwise -> Multisig.execute() (queues with timelock)
/// Already-queued txs can be accelerated by forwarding a self-call to
/// executeQueued — the multisig skips the ETA check for self-calls.
/// Singleton — one deployment serves all multisigs.
///
/// WARNING: Do NOT deploy at a vanity `0x1111` address (pre/post guard).
/// The Multisig hook call would hit this contract and revert.
contract TimelockExecutor {
    event ForwardEnabled(address indexed multisig, bool enabled);
    event Forwarded(address indexed multisig, bytes32 indexed hash);

    error InvalidSig();
    error Unauthorized();

    mapping(address multisig => bool) public forwardEnabled;

    constructor() payable {}

    function enableForward(bool enabled) public {
        forwardEnabled[msg.sender] = enabled;
        emit ForwardEnabled(msg.sender, enabled);
    }

    /// @dev Verify owner signatures and execute immediately via executor bypass.
    /// Cancel (target=multisig, selector=cancelQueued) requires threshold sigs
    /// and is always available. All other calls require all-owner sigs (unanimous)
    /// and forwardEnabled — the timelock is a security boundary that should only
    /// be bypassable when the multisig explicitly opts in.
    /// Supports both ECDSA (v>0) and onchain approvals (v=0, sender or pre-approved).
    function forward(address multisig, address target, uint256 value, bytes calldata data, bytes calldata sigs) public {
        uint256 required;
        if (target == multisig && data.length >= 4 && bytes4(data[:4]) == IMultisig.cancelQueued.selector) {
            required = IMultisig(multisig).threshold();
        } else {
            require(forwardEnabled[multisig], Unauthorized());
            required = IMultisig(multisig).ownerCount();
        }

        bytes32 hash = IMultisig(multisig).getTransactionHash(target, value, data, IMultisig(multisig).nonce());

        address prev;
        address signer;
        unchecked {
            require(sigs.length == required * 65, InvalidSig());
            for (uint256 i; i != required; ++i) {
                uint256 o = i * 65;
                if (uint8(sigs[o + 64]) == 0) {
                    signer = address(uint160(uint256(bytes32(sigs[o:o + 32]))));
                    require(msg.sender == signer || IMultisig(multisig).approved(signer, hash), InvalidSig());
                } else {
                    signer = ecrecover(hash, uint8(sigs[o + 64]), bytes32(sigs[o:o + 32]), bytes32(sigs[o + 32:o + 64]));
                }
                require(IMultisig(multisig).isOwner(signer) && signer > prev, InvalidSig());
                prev = signer;
            }
        }

        IMultisig(multisig).execute(target, value, data, "");
        emit Forwarded(multisig, hash);
    }
}
