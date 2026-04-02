// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import {Script, console} from "forge-std/Script.sol";

/// @title VanityMiner
/// @notice Mine CREATE2 salts for vanity addresses via SafeSummoner or MultisigFactory.
/// @dev Usage:
///   Set MODE env var to select:
///
///   MODE=factory (default) — Mine the MultisigFactory address via SafeSummoner.
///     DEPLOYER   — SafeSummoner address (default: 0x00000000004473e1f31C8266612e7FD5504e6f2a)
///     INIT_CODE  — Full creation bytecode of MultisigFactory (hex, no 0x prefix OK)
///     PREFIX     — Desired hex prefix (default: "0000")
///     CALLER     — (optional) msg.sender for front-run protection
///     OFFSET     — (optional) start nonce (default 0)
///     BATCH      — (optional) salts per run (default 1_000_000)
///
///   MODE=wallet — Mine multisig wallet addresses via MultisigFactory clone CREATE2.
///     FACTORY        — MultisigFactory address
///     IMPLEMENTATION — Multisig implementation address (factory.implementation())
///     PREFIX         — Desired hex prefix (default: "0000")
///     CALLER         — (optional) msg.sender, packed into upper 160 bits of salt
///     OFFSET         — (optional) start nonce (default 0)
///     BATCH          — (optional) salts per run (default 1_000_000)
///
///   Run:
///     forge script script/VanityMiner.sol -vvv
contract VanityMiner is Script {
    function run() public view {
        string memory mode = vm.envOr("MODE", string("factory"));

        if (keccak256(bytes(mode)) == keccak256("wallet")) {
            _mineWallet();
        } else {
            _mineFactory();
        }
    }

    /// @dev Mine the MultisigFactory address deployed via SafeSummoner.create2Deploy.
    function _mineFactory() internal view {
        address deployer = vm.envOr("DEPLOYER", address(0x00000000004473e1f31C8266612e7FD5504e6f2a));
        bytes memory initCode = vm.envBytes("INIT_CODE");
        string memory prefix = vm.envOr("PREFIX", string("0000"));
        address caller = vm.envOr("CALLER", address(0));
        uint256 offset = vm.envOr("OFFSET", uint256(0));
        uint256 batch = vm.envOr("BATCH", uint256(1_000_000));

        bytes32 initCodeHash = keccak256(initCode);
        bytes memory target = _hexToBytes(prefix);
        uint256 targetLen = target.length;

        console.log("=== VanityMiner (Factory via SafeSummoner) ===");
        console.log("Deployer:      ", deployer);
        console.log("InitCodeHash:  ");
        console.logBytes32(initCodeHash);
        console.log("Prefix:         0x%s", prefix);
        if (caller != address(0)) console.log("Caller:        ", caller);
        console.log("Searching %d salts from offset %d ...", batch, offset);
        console.log("");

        uint256 found;
        for (uint256 i = offset; i < offset + batch; i++) {
            bytes32 salt = caller == address(0) ? bytes32(i) : keccak256(abi.encodePacked(caller, i));

            address predicted = _predict(deployer, salt, initCodeHash);
            if (_matchesPrefix(predicted, target, targetLen)) {
                found++;
                console.log("MATCH #%d", found);
                console.log("  nonce:   %d", i);
                console.log("  salt:    ");
                console.logBytes32(salt);
                console.log("  address: ", predicted);
                console.log("");
            }
        }

        if (found == 0) {
            console.log("No matches found. Try increasing BATCH or shifting OFFSET.");
        } else {
            console.log("Found %d match(es).", found);
        }
    }

    /// @dev Mine multisig wallet addresses deployed via MultisigFactory clone CREATE2.
    function _mineWallet() internal view {
        address factory = vm.envAddress("FACTORY");
        address impl = vm.envAddress("IMPLEMENTATION");
        string memory prefix = vm.envOr("PREFIX", string("0000"));
        address caller = vm.envOr("CALLER", address(0));
        uint256 offset = vm.envOr("OFFSET", uint256(0));
        uint256 batch = vm.envOr("BATCH", uint256(1_000_000));

        bytes32 initCodeHash = _cloneInitCodeHash(impl);
        bytes memory target = _hexToBytes(prefix);
        uint256 targetLen = target.length;

        console.log("=== VanityMiner (Wallet via MultisigFactory) ===");
        console.log("Factory:       ", factory);
        console.log("Implementation:", impl);
        console.log("InitCodeHash:  ");
        console.logBytes32(initCodeHash);
        console.log("Prefix:         0x%s", prefix);
        if (caller != address(0)) console.log("Caller:        ", caller);
        console.log("Searching %d salts from offset %d ...", batch, offset);
        console.log("");

        uint256 found;
        for (uint256 i = offset; i < offset + batch; i++) {
            bytes32 salt = _buildWalletSalt(caller, i);
            address predicted = _predict(factory, salt, initCodeHash);

            if (_matchesPrefix(predicted, target, targetLen)) {
                found++;
                console.log("MATCH #%d", found);
                console.log("  nonce:   %d", i);
                console.log("  salt:    ");
                console.logBytes32(salt);
                console.log("  address: ", predicted);
                console.log("");
            }
        }

        if (found == 0) {
            console.log("No matches found. Try increasing BATCH or shifting OFFSET.");
        } else {
            console.log("Found %d match(es).", found);
        }
    }

    /// @dev Build salt for MultisigFactory.create().
    ///      Factory requires: salt >> 96 == 0 || salt >> 96 == uint160(msg.sender).
    ///      Packs caller into upper 160 bits, nonce into lower 96 bits.
    function _buildWalletSalt(address caller, uint256 nonce) internal pure returns (bytes32) {
        if (caller == address(0)) return bytes32(nonce);
        return bytes32(uint256(uint160(caller)) << 96 | nonce);
    }

    /// @dev Initcode hash for MultisigFactory's PUSH0 minimal proxy clone.
    ///      Layout (54 bytes):
    ///        602d5f8160095f39f35f5f365f5f37365f73  (18 bytes)
    ///        <implementation address>                (20 bytes)
    ///        5af43d5f5f3e6029573d5ffd5b3d5ff3      (16 bytes)
    function _cloneInitCodeHash(address impl) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(hex"602d5f8160095f39f35f5f365f5f37365f73", impl, hex"5af43d5f5f3e6029573d5ffd5b3d5ff3")
        );
    }

    function _predict(address deployer, bytes32 salt, bytes32 initCodeHash) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, initCodeHash)))));
    }

    function _matchesPrefix(address addr, bytes memory target, uint256 len) internal pure returns (bool) {
        bytes20 raw = bytes20(addr);
        for (uint256 i; i < len; i++) {
            if (raw[i] != target[i]) return false;
        }
        return true;
    }

    function _hexToBytes(string memory hex_) internal pure returns (bytes memory) {
        bytes memory h = bytes(hex_);
        require(h.length % 2 == 0, "hex prefix must be even length");
        bytes memory result = new bytes(h.length / 2);
        for (uint256 i; i < h.length; i += 2) {
            result[i / 2] = bytes1(_hexCharToNibble(h[i]) << 4 | _hexCharToNibble(h[i + 1]));
        }
        return result;
    }

    function _hexCharToNibble(bytes1 c) internal pure returns (uint8) {
        if (c >= "0" && c <= "9") return uint8(c) - 48;
        if (c >= "a" && c <= "f") return uint8(c) - 87;
        if (c >= "A" && c <= "F") return uint8(c) - 55;
        revert("invalid hex char");
    }
}
