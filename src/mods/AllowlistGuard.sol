// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @dev Pre-transaction guard that whitelists (target, selector) pairs.
/// Deploy at a vanity address with leading 0x1111 to activate as pre-guard.
/// Singleton — one deployment serves all multisigs, keyed by msg.sender.
contract AllowlistGuard {
    event AllowlistSet(address indexed multisig, address indexed target, bytes4 sel, bool allowed);

    error NotAllowed();
    error Unauthorized();

    mapping(address multisig => mapping(address target => mapping(bytes4 sel => bool))) public allowed;

    constructor() payable {}

    /// @dev Called by multisig as pre-guard. Calls targeting the guard itself
    /// are always allowed so owners can configure the allowlist after activation.
    /// Plain ETH transfers (empty calldata) require allowlisting bytes4(0).
    function execute(address target, uint256, bytes calldata data, bytes calldata) public payable {
        if (target == address(this)) return;
        bytes4 sel = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        require(allowed[msg.sender][target][sel], NotAllowed());
    }

    function set(address target, bytes4 sel, bool ok) public {
        allowed[msg.sender][target][sel] = ok;
        emit AllowlistSet(msg.sender, target, sel, ok);
    }
}
