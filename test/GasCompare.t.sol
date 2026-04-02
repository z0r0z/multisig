// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../src/Multisig.sol";

// A: create2(callvalue()) + init() — current approach
contract FactoryA {
    address public immutable implementation;

    constructor() payable {
        implementation = address(new Multisig{salt: bytes32(0)}());
        address[] memory lock = new address[](1);
        lock[0] = address(1);
        Multisig(payable(implementation)).init(lock, 1);
    }

    function create(address[] calldata _owners, uint128 _threshold, uint256 salt)
        public
        payable
        returns (address wallet)
    {
        address impl = implementation;
        assembly ("memory-safe") {
            mstore(0x24, 0x5af43d5f5f3e6029573d5ffd5b3d5ff3)
            mstore(0x14, impl)
            mstore(0x00, 0x602d5f8160095f39f35f5f365f5f37365f73)
            wallet := create2(callvalue(), 0x0e, 0x36, salt)
            if iszero(wallet) { revert(0, 0) }
            mstore(0x24, 0)
        }
        Multisig(payable(wallet)).init(_owners, _threshold);
    }
}

// B: create2(0) + init{value: msg.value}() — previous approach
contract FactoryB {
    address public immutable implementation;

    constructor() payable {
        implementation = address(new Multisig{salt: bytes32(0)}());
        address[] memory lock = new address[](1);
        lock[0] = address(1);
        Multisig(payable(implementation)).init(lock, 1);
    }

    function create(address[] calldata _owners, uint128 _threshold, uint256 salt)
        public
        payable
        returns (address wallet)
    {
        address impl = implementation;
        assembly ("memory-safe") {
            mstore(0x24, 0x5af43d5f5f3e6029573d5ffd5b3d5ff3)
            mstore(0x14, impl)
            mstore(0x00, 0x602d5f8160095f39f35f5f365f5f37365f73)
            wallet := create2(0, 0x0e, 0x36, salt)
            if iszero(wallet) { revert(0, 0) }
            mstore(0x24, 0)
        }
        Multisig(payable(wallet)).init{value: msg.value}(_owners, _threshold);
    }
}

contract GasCompareTest is Test {
    FactoryA factoryA;
    FactoryB factoryB;

    function setUp() public {
        factoryA = new FactoryA();
        factoryB = new FactoryB();
    }

    function _owners3() internal pure returns (address[] memory) {
        address[] memory arr = new address[](3);
        arr[0] = address(0x1111);
        arr[1] = address(0x2222);
        arr[2] = address(0x3333);
        return arr;
    }

    function test_gas_callvalue_create2() public {
        factoryA.create(_owners3(), 2, 0);
    }

    function test_gas_value_in_init() public {
        factoryB.create(_owners3(), 2, 1);
    }
}
