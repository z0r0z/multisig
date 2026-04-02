// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../src/Multisig.sol";

/// @notice Lean gas benchmarks for common multisig operations.
/// @dev Run: forge test --mc GasTest -vv
contract GasTest is Test {
    MultisigFactory factory;

    uint256 pk1 = 0xA1;
    uint256 pk2 = 0xB2;
    uint256 pk3 = 0xC3;

    address owner1;
    address owner2;
    address owner3;

    address receiver;
    address executorAddr = address(0xE0);

    bytes32 constant EXECUTE_TYPEHASH = keccak256("Execute(address target,uint256 value,bytes data,uint48 nonce)");

    function setUp() public {
        owner1 = vm.addr(pk1);
        owner2 = vm.addr(pk2);
        owner3 = vm.addr(pk3);

        factory = new MultisigFactory();
        receiver = makeAddr("receiver");
        vm.deal(address(this), 100 ether);
    }

    // ───────── Helpers ─────────

    function _sortedOwners() internal view returns (address[] memory) {
        address[] memory arr = new address[](3);
        arr[0] = owner1;
        arr[1] = owner2;
        arr[2] = owner3;
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (arr[i] > arr[j]) (arr[i], arr[j]) = (arr[j], arr[i]);
            }
        }
        return arr;
    }

    function _sortedPks() internal view returns (uint256[] memory) {
        address[] memory addrs = _sortedOwners();
        uint256[] memory pks = new uint256[](3);
        for (uint256 i; i < 3; ++i) {
            if (addrs[i] == owner1) pks[i] = pk1;
            else if (addrs[i] == owner2) pks[i] = pk2;
            else pks[i] = pk3;
        }
        return pks;
    }

    function _sign(Multisig w, address to, uint256 value, bytes memory data, uint256 n)
        internal
        view
        returns (bytes memory sigs)
    {
        bytes32 hash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                w.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(EXECUTE_TYPEHASH, to, value, keccak256(data), w.nonce()))
            )
        );
        uint256[] memory pks = _sortedPks();
        sigs = new bytes(n * 65);
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], hash);
            uint256 o = i * 65;
            assembly {
                let ptr := add(add(sigs, 0x20), o)
                mstore(ptr, r)
                mstore(add(ptr, 0x20), s)
                mstore8(add(ptr, 0x40), v)
            }
        }
    }

    uint256 salt;

    function _deploy(uint256 threshold, uint32 delay, address exec) internal returns (Multisig w) {
        address[] memory owners = _sortedOwners();
        w = Multisig(payable(factory.create{value: 1 ether}(owners, delay, threshold, exec, salt++)));
        // warm all storage slots to measure steady-state gas (not cold-access)
        w.nonce();
        w.threshold();
        w.delay();
        w.executor();
    }

    // ───────── Deploy ─────────

    function test_gas_deploy() public {
        address[] memory owners = _sortedOwners();
        uint256 g = gasleft();
        factory.create(owners, 0, 2, address(0), salt++);
        g -= gasleft();
        emit log_named_uint("deploy 2-of-3", g);
    }

    // ───────── ETH transfers by signer count ─────────

    function test_gas_execute_1of3() public {
        Multisig w = _deploy(1, 0, address(0));
        bytes memory sigs = _sign(w, receiver, 0.1 ether, "", 1);
        uint256 g = gasleft();
        w.execute(receiver, 0.1 ether, "", sigs);
        g -= gasleft();
        emit log_named_uint("execute ETH 1-of-3", g);
    }

    function test_gas_execute_2of3() public {
        Multisig w = _deploy(2, 0, address(0));
        bytes memory sigs = _sign(w, receiver, 0.1 ether, "", 2);
        uint256 g = gasleft();
        w.execute(receiver, 0.1 ether, "", sigs);
        g -= gasleft();
        emit log_named_uint("execute ETH 2-of-3", g);
    }

    function test_gas_execute_3of3() public {
        Multisig w = _deploy(3, 0, address(0));
        bytes memory sigs = _sign(w, receiver, 0.1 ether, "", 3);
        uint256 g = gasleft();
        w.execute(receiver, 0.1 ether, "", sigs);
        g -= gasleft();
        emit log_named_uint("execute ETH 3-of-3", g);
    }

    // ───────── Executor ─────────

    function test_gas_execute_executor() public {
        Multisig w = _deploy(2, 0, executorAddr);
        vm.prank(executorAddr);
        uint256 g = gasleft();
        w.execute(receiver, 0.1 ether, "", "");
        g -= gasleft();
        emit log_named_uint("execute ETH via executor", g);
    }

    // ───────── Timelock: queue + executeQueued ─────────

    function test_gas_queue() public {
        Multisig w = _deploy(2, 1 days, address(0));
        bytes memory sigs = _sign(w, receiver, 0.1 ether, "", 2);
        uint256 g = gasleft();
        w.execute(receiver, 0.1 ether, "", sigs);
        g -= gasleft();
        emit log_named_uint("queue (execute w/ delay)", g);
    }

    function test_gas_executeQueued() public {
        Multisig w = _deploy(2, 1 days, address(0));
        bytes memory sigs = _sign(w, receiver, 0.1 ether, "", 2);
        w.execute(receiver, 0.1 ether, "", sigs);
        vm.warp(block.timestamp + 1 days);
        uint256 g = gasleft();
        w.executeQueued(receiver, 0.1 ether, "", 0);
        g -= gasleft();
        emit log_named_uint("executeQueued ETH", g);
    }

    // ───────── Batch ─────────

    function test_gas_batch_3() public {
        Multisig w = _deploy(2, 0, address(0));

        address[] memory targets = new address[](3);
        uint256[] memory values = new uint256[](3);
        bytes[] memory datas = new bytes[](3);
        for (uint256 i; i < 3; ++i) {
            targets[i] = receiver;
            values[i] = 0.1 ether;
            datas[i] = "";
        }
        bytes memory data = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(w, address(w), 0, data, 2);
        uint256 g = gasleft();
        w.execute(address(w), 0, data, sigs);
        g -= gasleft();
        emit log_named_uint("batch 3 ETH transfers", g);
    }
}
