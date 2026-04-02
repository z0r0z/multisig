// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../src/Multisig.sol";

contract Receiver {
    fallback() external payable {}
}

contract EIP7702Test is Test {
    Multisig implementation;

    uint256 eoaPk = 0xE0A;
    address eoa;

    uint256 pk1 = 0xA1;
    uint256 pk2 = 0xB2;
    uint256 pk3 = 0xC3;

    address owner1;
    address owner2;
    address owner3;

    bytes32 constant EXECUTE_TYPEHASH = keccak256("Execute(address target,uint256 value,bytes data,uint64 nonce)");
    bytes32 constant SAFE_MSG_TYPEHASH = keccak256("SafeMessage(bytes32 hash)");

    function setUp() public {
        eoa = vm.addr(eoaPk);
        owner1 = vm.addr(pk1);
        owner2 = vm.addr(pk2);
        owner3 = vm.addr(pk3);

        // Deploy a standalone Multisig implementation for delegation
        implementation = new Multisig();
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

    function _sortedPKs(uint256[] memory pks) internal pure returns (uint256[] memory) {
        for (uint256 i; i < pks.length; ++i) {
            for (uint256 j = i + 1; j < pks.length; ++j) {
                if (vm.addr(pks[i]) > vm.addr(pks[j])) (pks[i], pks[j]) = (pks[j], pks[i]);
            }
        }
        return pks;
    }

    function _pks2() internal view returns (uint256[] memory) {
        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk2;
        return _sortedPKs(pks);
    }

    function _pks3() internal view returns (uint256[] memory) {
        uint256[] memory pks = new uint256[](3);
        pks[0] = pk1;
        pks[1] = pk2;
        pks[2] = pk3;
        return _sortedPKs(pks);
    }

    function _domainSeparator(address walletAddr) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Multisig"),
                keccak256("1"),
                block.chainid,
                walletAddr
            )
        );
    }

    function _digest(address wallet, address to, uint256 value, bytes memory data) internal view returns (bytes32) {
        Multisig w = Multisig(payable(wallet));
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                w.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(EXECUTE_TYPEHASH, to, value, keccak256(data), w.nonce()))
            )
        );
    }

    function _signHash(bytes32 hash, uint256[] memory pks) internal pure returns (bytes memory sigs) {
        sigs = new bytes(pks.length * 65);
        for (uint256 i; i < pks.length; ++i) {
            (uint8 vi, bytes32 ri, bytes32 si) = vm.sign(pks[i], hash);
            uint256 o = i * 65;
            assembly {
                let ptr := add(add(sigs, 0x20), o)
                mstore(ptr, ri)
                mstore(add(ptr, 0x20), si)
                mstore8(add(ptr, 0x40), vi)
            }
        }
    }

    function _sign(address wallet, address to, uint256 value, bytes memory data, uint256[] memory pks)
        internal
        view
        returns (bytes memory)
    {
        return _signHash(_digest(wallet, to, value, data), pks);
    }

    /// @dev Delegate the EOA to the Multisig implementation and call init.
    function _delegateAndInit(uint64 thresholdVal) internal {
        Vm.SignedDelegation memory sd = vm.signDelegation(address(implementation), eoaPk);
        vm.attachDelegation(sd);
        vm.prank(eoa);
        Multisig(payable(eoa)).init(_sortedOwners(), 0, thresholdVal);
    }

    // ═══════════════════════════════════════════
    //         EIP-7702 DELEGATION TESTS
    // ═══════════════════════════════════════════

    function test_7702_initViaSelfCall() public {
        _delegateAndInit(2);

        Multisig wallet = Multisig(payable(eoa));
        assertEq(wallet.threshold(), 2);
        assertEq(wallet.nonce(), 0);

        address[] memory sorted = _sortedOwners();
        for (uint256 i; i < 3; ++i) {
            assertTrue(wallet.isOwner(sorted[i]));
        }
        assertEq(wallet.getOwners().length, 3);
    }

    function test_7702_domainSeparatorUsesEOA() public {
        _delegateAndInit(2);

        assertEq(Multisig(payable(eoa)).DOMAIN_SEPARATOR(), _domainSeparator(eoa));
    }

    function test_7702_revertDoubleInit() public {
        _delegateAndInit(2);

        vm.prank(eoa);
        vm.expectRevert(Multisig.InvalidConfig.selector);
        Multisig(payable(eoa)).init(_sortedOwners(), 0, 2);
    }

    // ═══════════════════════════════════════════
    //           EIP-7702 EXECUTE TESTS
    // ═══════════════════════════════════════════

    function test_7702_executeSendETH() public {
        _delegateAndInit(2);
        vm.deal(eoa, 5 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(eoa, receiver, 1 ether, "", _pks2());
        Multisig(payable(eoa)).execute(receiver, 1 ether, "", sigs);

        assertEq(receiver.balance, 1 ether);
        assertEq(eoa.balance, 4 ether);
        assertEq(Multisig(payable(eoa)).nonce(), 1);
    }

    function test_7702_executeCallWithData() public {
        _delegateAndInit(2);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (1));
        bytes memory sigs = _sign(eoa, eoa, 0, data, _pks2());

        Multisig(payable(eoa)).execute(eoa, 0, data, sigs);
        assertEq(Multisig(payable(eoa)).threshold(), 1);
    }

    function test_7702_executeIncrementsNonce() public {
        _delegateAndInit(2);
        vm.deal(eoa, 10 ether);
        address receiver = address(new Receiver());

        for (uint256 i; i < 3; ++i) {
            bytes memory sigs = _sign(eoa, receiver, 1 ether, "", _pks2());
            Multisig(payable(eoa)).execute(receiver, 1 ether, "", sigs);
            assertEq(Multisig(payable(eoa)).nonce(), i + 1);
        }
    }

    // ═══════════════════════════════════════════
    //      EIP-7702 EOA SUPERUSER TESTS
    // ═══════════════════════════════════════════

    function test_7702_eoaCanCallOnlySelfDirectly() public {
        _delegateAndInit(2);

        // EOA calls setThreshold on itself — msg.sender == address(this)
        vm.prank(eoa);
        Multisig(payable(eoa)).setThreshold(1);
        assertEq(Multisig(payable(eoa)).threshold(), 1);
    }

    function test_7702_eoaCanAddOwnerDirectly() public {
        _delegateAndInit(2);
        address newOwner = address(0xBEEF);

        vm.prank(eoa);
        Multisig(payable(eoa)).addOwner(newOwner);
        assertTrue(Multisig(payable(eoa)).isOwner(newOwner));
    }

    function test_7702_eoaCanRemoveOwnerDirectly() public {
        _delegateAndInit(2);
        address[] memory sorted = _sortedOwners();

        vm.prank(eoa);
        Multisig(payable(eoa)).removeOwner(sorted[0]);
        assertFalse(Multisig(payable(eoa)).isOwner(sorted[0]));
    }

    function test_7702_nonEoaCannotCallOnlySelf() public {
        _delegateAndInit(2);

        vm.prank(address(0xDEAD));
        vm.expectRevert(Multisig.Unauthorized.selector);
        Multisig(payable(eoa)).setThreshold(1);
    }

    // ═══════════════════════════════════════════
    //           EIP-7702 BATCH TESTS
    // ═══════════════════════════════════════════

    function test_7702_batchViaExecute() public {
        _delegateAndInit(2);

        address newOwner = address(0xBEEF);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = eoa;
        targets[1] = eoa;
        datas[0] = abi.encodeCall(Multisig.addOwner, (newOwner));
        datas[1] = abi.encodeCall(Multisig.setThreshold, (3));

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(eoa, eoa, 0, batchData, _pks2());

        Multisig(payable(eoa)).execute(eoa, 0, batchData, sigs);
        assertTrue(Multisig(payable(eoa)).isOwner(newOwner));
        assertEq(Multisig(payable(eoa)).threshold(), 3);
    }

    function test_7702_batchDirectlyAsEoa() public {
        _delegateAndInit(2);

        address newOwner = address(0xBEEF);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = eoa;
        targets[1] = eoa;
        datas[0] = abi.encodeCall(Multisig.addOwner, (newOwner));
        datas[1] = abi.encodeCall(Multisig.setThreshold, (3));

        vm.prank(eoa);
        Multisig(payable(eoa)).batch(targets, values, datas);
        assertTrue(Multisig(payable(eoa)).isOwner(newOwner));
        assertEq(Multisig(payable(eoa)).threshold(), 3);
    }

    // ═══════════════════════════════════════════
    //         EIP-7702 EIP-1271 TESTS
    // ═══════════════════════════════════════════

    function test_7702_isValidSignature() public {
        _delegateAndInit(2);

        Multisig wallet = Multisig(payable(eoa));
        bytes32 hash = keccak256("test message");
        bytes32 safe = keccak256(
            abi.encodePacked("\x19\x01", wallet.DOMAIN_SEPARATOR(), keccak256(abi.encode(SAFE_MSG_TYPEHASH, hash)))
        );

        bytes memory sigs = _signHash(safe, _pks2());
        assertEq(wallet.isValidSignature(hash, sigs), bytes4(0x1626ba7e));
    }

    // ═══════════════════════════════════════════
    //         EIP-7702 RECEIVE TESTS
    // ═══════════════════════════════════════════

    function test_7702_receiveETH() public {
        _delegateAndInit(2);

        vm.deal(address(this), 1 ether);
        (bool ok,) = eoa.call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(eoa.balance, 1 ether);
    }

    function test_7702_onERC721Received() public {
        _delegateAndInit(2);

        bytes4 sel = bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
        (bool ok, bytes memory ret) = eoa.call(abi.encodeWithSelector(sel, address(0), address(0), uint256(0), ""));
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes4)), sel);
    }

    // ═══════════════════════════════════════════
    //           TIMELOCK TESTS
    // ═══════════════════════════════════════════

    function _delegateInitAndSetDelay(uint64 _delay) internal {
        _delegateAndInit(2);
        vm.prank(eoa);
        Multisig(payable(eoa)).setDelay(_delay);
    }

    function test_timelock_executeQueuesWhenDelaySet() public {
        _delegateInitAndSetDelay(1 days);
        Multisig wallet = Multisig(payable(eoa));
        vm.deal(eoa, 1 ether);
        address receiver = address(new Receiver());

        uint64 nonceAtQueue = wallet.nonce();
        bytes memory sigs = _sign(eoa, receiver, 1 ether, "", _pks2());

        vm.expectEmit(false, false, false, true);
        emit Multisig.Queued(bytes32(0), nonceAtQueue, block.timestamp + 1 days);
        wallet.execute(receiver, 1 ether, "", sigs);

        // ETH stays in the wallet, nonce advanced, tx is queued
        assertEq(receiver.balance, 0);
        assertEq(wallet.nonce(), nonceAtQueue + 1);
    }

    function test_timelock_executeQueuedAfterDelay() public {
        _delegateInitAndSetDelay(1 days);
        Multisig wallet = Multisig(payable(eoa));
        vm.deal(eoa, 1 ether);
        address receiver = address(new Receiver());

        uint64 nonceAtQueue = wallet.nonce();
        bytes memory sigs = _sign(eoa, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        // warp past delay
        vm.warp(block.timestamp + 1 days);
        wallet.executeQueued(receiver, 1 ether, "", nonceAtQueue);

        assertEq(receiver.balance, 1 ether);
    }

    function test_timelock_revertExecuteQueuedTooEarly() public {
        _delegateInitAndSetDelay(1 days);
        Multisig wallet = Multisig(payable(eoa));
        vm.deal(eoa, 1 ether);
        address receiver = address(new Receiver());

        uint64 nonceAtQueue = wallet.nonce();
        bytes memory sigs = _sign(eoa, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        // warp to just before eta
        vm.warp(block.timestamp + 1 days - 1);
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, block.timestamp + 1));
        wallet.executeQueued(receiver, 1 ether, "", nonceAtQueue);
    }

    function test_timelock_revertExecuteQueuedNotQueued() public {
        _delegateInitAndSetDelay(1 days);
        Multisig wallet = Multisig(payable(eoa));

        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(address(0xBEEF), 0, "", 0);
    }

    function test_timelock_revertExecuteQueuedReplay() public {
        _delegateInitAndSetDelay(1 days);
        Multisig wallet = Multisig(payable(eoa));
        vm.deal(eoa, 2 ether);
        address receiver = address(new Receiver());

        uint64 n = wallet.nonce();
        bytes memory sigs = _sign(eoa, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        wallet.executeQueued(receiver, 1 ether, "", n);

        // second attempt reverts — entry was deleted
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(receiver, 1 ether, "", n);
    }

    function test_timelock_delayZeroExecutesImmediately() public {
        _delegateAndInit(2);
        // delay is 0 by default
        Multisig wallet = Multisig(payable(eoa));
        vm.deal(eoa, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(eoa, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        assertEq(receiver.balance, 1 ether);
    }

    function test_timelock_eoaSuperuserBypassesTimelock() public {
        _delegateInitAndSetDelay(1 days);

        // EOA calls setThreshold directly — no timelock
        vm.prank(eoa);
        Multisig(payable(eoa)).setThreshold(1);
        assertEq(Multisig(payable(eoa)).threshold(), 1);
    }

    function test_timelock_setDelay() public {
        _delegateAndInit(2);
        Multisig wallet = Multisig(payable(eoa));

        vm.prank(eoa);
        wallet.setDelay(7 days);
        assertEq(wallet.delay(), 7 days);

        vm.prank(eoa);
        wallet.setDelay(0);
        assertEq(wallet.delay(), 0);
    }

    function test_timelock_executeQueuedAnyone() public {
        _delegateInitAndSetDelay(1 days);
        Multisig wallet = Multisig(payable(eoa));
        vm.deal(eoa, 1 ether);
        address receiver = address(new Receiver());

        uint64 n = wallet.nonce();
        bytes memory sigs = _sign(eoa, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);

        // anyone can relay executeQueued
        vm.prank(address(0xCAFE));
        wallet.executeQueued(receiver, 1 ether, "", n);
        assertEq(receiver.balance, 1 ether);
    }
}
