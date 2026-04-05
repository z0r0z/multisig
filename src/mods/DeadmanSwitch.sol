// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {IMultisig} from "./interfaces/IMultisig.sol";

/// @dev Post-guard and executor that enables a beneficiary to sweep funds
/// after a period of inactivity. Deploy at a vanity address with trailing
/// 0x1111 so each multisig execution resets the heartbeat via post-guard.
/// Singleton — one deployment serves all multisigs, keyed by msg.sender.
contract DeadmanSwitch {
    event Claimed(address indexed multisig, address indexed beneficiary, uint256 amount);
    event Configured(address indexed multisig, address indexed beneficiary, uint256 timeout);

    error StillAlive();
    error Unauthorized();
    error InvalidConfig();

    struct Config {
        address beneficiary;
        uint256 timeout;
        uint256 lastActivity;
    }

    mapping(address multisig => Config) public configs;

    constructor() payable {}

    /// @dev Called as post-guard after every multisig execution. Resets heartbeat.
    function execute(address, uint256, bytes calldata, bytes calldata) public payable {
        configs[msg.sender].lastActivity = block.timestamp;
    }

    function configure(address _beneficiary, uint256 _timeout) public {
        require(uint160(address(this)) & 0xFFFF == 0x1111, InvalidConfig());
        configs[msg.sender] = Config(_beneficiary, _timeout, block.timestamp);
        emit Configured(msg.sender, _beneficiary, _timeout);
    }

    function claim(address multisig) public {
        Config storage c = configs[multisig];
        require(msg.sender == c.beneficiary, Unauthorized());
        require(block.timestamp >= c.lastActivity + c.timeout, StillAlive());
        uint256 amount = multisig.balance;
        require(amount != 0, StillAlive());
        IMultisig(multisig).execute(msg.sender, amount, "", "");
        emit Claimed(multisig, msg.sender, amount);
    }
}
