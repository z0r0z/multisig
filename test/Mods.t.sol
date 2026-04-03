// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../src/Multisig.sol";
import "../src/mods/AllowlistGuard.sol";
import "../src/mods/SpendingAllowance.sol";
import "../src/mods/SocialRecovery.sol";
import "../src/mods/DeadmanSwitch.sol";
import "../src/mods/CancelTx.sol";

contract Sink {
    fallback() external payable {}
}

contract ModsTest is Test {
    MultisigFactory factory;

    uint256 pk1 = 0xA1;
    uint256 pk2 = 0xB2;
    uint256 pk3 = 0xC3;

    address owner1;
    address owner2;
    address owner3;

    // Vanity addresses for guard activation
    address constant PRE_GUARD = address(uint160(0x1111) << 144);
    address constant POST_GUARD = address(0x1111);

    SpendingAllowance spending;
    SocialRecovery recovery;
    CancelTx cancelMod;

    Sink sink;
    address spender = address(0x5555);
    address guardian = address(0x6666);
    address beneficiary = address(0x7777);

    bytes32 constant EXECUTE_TYPEHASH = keccak256("Execute(address target,uint256 value,bytes data,uint32 nonce)");

    uint256 nextSalt;

    function setUp() public {
        owner1 = vm.addr(pk1);
        owner2 = vm.addr(pk2);
        owner3 = vm.addr(pk3);

        factory = new MultisigFactory();
        sink = new Sink();

        spending = new SpendingAllowance();
        recovery = new SocialRecovery();
        cancelMod = new CancelTx();

        vm.etch(PRE_GUARD, address(new AllowlistGuard()).code);
        vm.etch(POST_GUARD, address(new DeadmanSwitch()).code);
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

    function _deploy(uint128 threshold) internal returns (Multisig) {
        return Multisig(payable(factory.create(_sortedOwners(), 0, threshold, address(0), nextSalt++)));
    }

    function _deployFunded(uint128 threshold, uint256 amount) internal returns (Multisig) {
        vm.deal(address(this), amount);
        return Multisig(payable(factory.create{value: amount}(_sortedOwners(), 0, threshold, address(0), nextSalt++)));
    }

    function _digest(Multisig w, address to, uint256 value, bytes memory data) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                w.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(EXECUTE_TYPEHASH, to, value, keccak256(data), w.nonce()))
            )
        );
    }

    function _sign(Multisig w, address to, uint256 value, bytes memory data, uint256[] memory pks)
        internal
        view
        returns (bytes memory sigs)
    {
        bytes32 hash = _digest(w, to, value, data);
        sigs = new bytes(pks.length * 65);
        for (uint256 i; i < pks.length; ++i) {
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

    /// @dev Sign and execute in one call (threshold-2 wallet).
    function _exec(Multisig w, address to, uint256 value, bytes memory data) internal {
        w.execute(to, value, data, _sign(w, to, value, data, _pks2()));
    }

    /// @dev Build single-element call arrays for createWithCalls.
    function _callArrays(address target, bytes memory data)
        internal
        pure
        returns (address[] memory targets, uint256[] memory values, bytes[] memory datas)
    {
        targets = new address[](1);
        values = new uint256[](1);
        datas = new bytes[](1);
        targets[0] = target;
        datas[0] = data;
    }

    /// @dev Build two-element call arrays for createWithCalls.
    function _callArrays2(address t0, bytes memory d0, address t1, bytes memory d1)
        internal
        pure
        returns (address[] memory targets, uint256[] memory values, bytes[] memory datas)
    {
        targets = new address[](2);
        values = new uint256[](2);
        datas = new bytes[](2);
        targets[0] = t0;
        datas[0] = d0;
        targets[1] = t1;
        datas[1] = d1;
    }

    // ═══════════════════════════════════════════
    //           ALLOWLIST GUARD TESTS
    // ═══════════════════════════════════════════

    function test_allowlist_createWithCalls() public {
        (address[] memory t, uint256[] memory v, bytes[] memory d) =
            _callArrays(PRE_GUARD, abi.encodeCall(AllowlistGuard.set, (address(sink), bytes4(0), true)));

        vm.deal(address(this), 2 ether);
        Multisig w = Multisig(
            payable(factory.createWithCalls{value: 2 ether}(_sortedOwners(), 0, 2, PRE_GUARD, nextSalt++, t, v, d))
        );

        // Allowed call succeeds
        w.execute(address(sink), 1 ether, "", _sign(w, address(sink), 1 ether, "", _pks2()));
        assertEq(address(sink).balance, 1 ether);

        // Unlisted target reverts (sign before expectRevert to avoid consuming view calls)
        bytes memory sigs = _sign(w, spender, 1 ether, "", _pks2());
        vm.expectRevert(AllowlistGuard.NotAllowed.selector);
        w.execute(spender, 1 ether, "", sigs);
    }

    function test_allowlist_addedLater() public {
        Multisig w = _deployFunded(2, 2 ether);

        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (PRE_GUARD)));
        _exec(w, PRE_GUARD, 0, abi.encodeCall(AllowlistGuard.set, (address(sink), bytes4(0), true)));

        // Allowed
        w.execute(address(sink), 1 ether, "", _sign(w, address(sink), 1 ether, "", _pks2()));
        assertEq(address(sink).balance, 1 ether);

        // Unlisted
        bytes memory sigs = _sign(w, spender, 1 ether, "", _pks2());
        vm.expectRevert(AllowlistGuard.NotAllowed.selector);
        w.execute(spender, 1 ether, "", sigs);
    }

    function test_allowlist_blocksUnlistedSelector() public {
        Multisig w = _deployFunded(2, 1 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (PRE_GUARD)));
        _exec(w, PRE_GUARD, 0, abi.encodeCall(AllowlistGuard.set, (address(w), Multisig.setThreshold.selector, true)));

        // Allowed selector
        bytes memory ok = abi.encodeCall(Multisig.setThreshold, (2));
        w.execute(address(w), 0, ok, _sign(w, address(w), 0, ok, _pks2()));

        // Unlisted selector
        bytes memory bad = abi.encodeCall(Multisig.addOwner, (address(0x9999)));
        bytes memory sigs = _sign(w, address(w), 0, bad, _pks2());
        vm.expectRevert(AllowlistGuard.NotAllowed.selector);
        w.execute(address(w), 0, bad, sigs);
    }

    function test_allowlist_allowsSelfConfig() public {
        Multisig w = _deployFunded(2, 1 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (PRE_GUARD)));

        // Calls targeting the guard itself bypass the allowlist
        _exec(w, PRE_GUARD, 0, abi.encodeCall(AllowlistGuard.set, (address(sink), bytes4(0), true)));
        assertTrue(AllowlistGuard(PRE_GUARD).allowed(address(w), address(sink), bytes4(0)));
    }

    function test_allowlist_emitsEvent() public {
        Multisig w = _deployFunded(2, 1 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (PRE_GUARD)));

        vm.expectEmit(true, true, false, true, PRE_GUARD);
        emit AllowlistGuard.AllowlistSet(address(w), address(sink), bytes4(0), true);
        _exec(w, PRE_GUARD, 0, abi.encodeCall(AllowlistGuard.set, (address(sink), bytes4(0), true)));
    }

    // ═══════════════════════════════════════════
    //        SPENDING ALLOWANCE TESTS
    // ═══════════════════════════════════════════

    function test_spending_createWithCalls() public {
        (address[] memory t, uint256[] memory v, bytes[] memory d) =
            _callArrays(address(spending), abi.encodeCall(SpendingAllowance.configure, (spender, 1 ether, 1 days)));

        vm.deal(address(this), 5 ether);
        Multisig w = Multisig(
            payable(factory.createWithCalls{value: 5 ether}(
                    _sortedOwners(), 0, 2, address(spending), nextSalt++, t, v, d
                ))
        );

        vm.prank(spender);
        spending.spend(address(w), address(sink), 1 ether);
        assertEq(address(sink).balance, 1 ether);
    }

    function test_spending_addedLater() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (address(spending))));
        _exec(w, address(spending), 0, abi.encodeCall(SpendingAllowance.configure, (spender, 1 ether, 1 days)));

        vm.prank(spender);
        spending.spend(address(w), address(sink), 0.5 ether);
        assertEq(address(sink).balance, 0.5 ether);
    }

    function test_spending_overLimit() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (address(spending))));
        _exec(w, address(spending), 0, abi.encodeCall(SpendingAllowance.configure, (spender, 1 ether, 1 days)));

        vm.prank(spender);
        vm.expectRevert(SpendingAllowance.OverLimit.selector);
        spending.spend(address(w), address(sink), 2 ether);
    }

    function test_spending_periodReset() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (address(spending))));
        _exec(w, address(spending), 0, abi.encodeCall(SpendingAllowance.configure, (spender, 1 ether, 1 days)));

        // Exhaust allowance
        vm.prank(spender);
        spending.spend(address(w), address(sink), 1 ether);

        vm.prank(spender);
        vm.expectRevert(SpendingAllowance.OverLimit.selector);
        spending.spend(address(w), address(sink), 0.5 ether);

        // Warp past period — allowance resets
        vm.warp(block.timestamp + 1 days);
        vm.prank(spender);
        spending.spend(address(w), address(sink), 1 ether);
        assertEq(address(sink).balance, 2 ether);
    }

    function test_spending_revertUnauthorized() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (address(spending))));
        _exec(w, address(spending), 0, abi.encodeCall(SpendingAllowance.configure, (spender, 1 ether, 1 days)));

        vm.prank(address(0xBAD));
        vm.expectRevert(SpendingAllowance.Unauthorized.selector);
        spending.spend(address(w), address(sink), 0.5 ether);
    }

    // ═══════════════════════════════════════════
    //          RECOVERY MODULE TESTS
    // ═══════════════════════════════════════════

    function test_recovery_createWithCalls() public {
        (address[] memory t, uint256[] memory v, bytes[] memory d) = _callArrays2(
            address(recovery),
            abi.encodeCall(SocialRecovery.setGuardian, (guardian, true)),
            address(recovery),
            abi.encodeCall(SocialRecovery.setDelay, (1 days))
        );

        Multisig w =
            Multisig(payable(factory.createWithCalls(_sortedOwners(), 0, 2, address(recovery), nextSalt++, t, v, d)));

        assertTrue(recovery.isGuardian(address(w), guardian));
        assertEq(recovery.delay(address(w)), 1 days);

        // Guardian proposes adding a new owner
        address newOwner = vm.addr(0xD4);
        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        vm.prank(guardian);
        recovery.propose(address(w), address(w), 0, data);

        vm.warp(block.timestamp + 1 days);
        recovery.finalize(address(w), address(w), 0, data);
        assertTrue(w.isOwner(newOwner));
    }

    function test_recovery_addedLater() public {
        Multisig w = _deploy(2);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (address(recovery))));
        _exec(w, address(recovery), 0, abi.encodeCall(SocialRecovery.setGuardian, (guardian, true)));
        _exec(w, address(recovery), 0, abi.encodeCall(SocialRecovery.setDelay, (1 days)));

        address newOwner = vm.addr(0xD4);
        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        vm.prank(guardian);
        recovery.propose(address(w), address(w), 0, data);

        vm.warp(block.timestamp + 1 days);
        recovery.finalize(address(w), address(w), 0, data);
        assertTrue(w.isOwner(newOwner));
    }

    function test_recovery_revertBeforeDelay() public {
        Multisig w = _deploy(2);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (address(recovery))));
        _exec(w, address(recovery), 0, abi.encodeCall(SocialRecovery.setGuardian, (guardian, true)));
        _exec(w, address(recovery), 0, abi.encodeCall(SocialRecovery.setDelay, (1 days)));

        bytes memory data = abi.encodeCall(Multisig.addOwner, (vm.addr(0xD4)));
        vm.prank(guardian);
        recovery.propose(address(w), address(w), 0, data);

        vm.expectRevert(SocialRecovery.NotReady.selector);
        recovery.finalize(address(w), address(w), 0, data);
    }

    function test_recovery_cancel() public {
        Multisig w = _deploy(2);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (address(recovery))));
        _exec(w, address(recovery), 0, abi.encodeCall(SocialRecovery.setGuardian, (guardian, true)));
        _exec(w, address(recovery), 0, abi.encodeCall(SocialRecovery.setDelay, (1 days)));

        bytes memory data = abi.encodeCall(Multisig.addOwner, (vm.addr(0xD4)));
        vm.prank(guardian);
        recovery.propose(address(w), address(w), 0, data);

        vm.prank(guardian);
        recovery.cancel(address(w));

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(SocialRecovery.NotReady.selector);
        recovery.finalize(address(w), address(w), 0, data);
    }

    function test_recovery_revertUnauthorizedPropose() public {
        Multisig w = _deploy(2);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (address(recovery))));
        _exec(w, address(recovery), 0, abi.encodeCall(SocialRecovery.setGuardian, (guardian, true)));

        vm.prank(address(0xBAD));
        vm.expectRevert(SocialRecovery.Unauthorized.selector);
        recovery.propose(address(w), address(w), 0, abi.encodeCall(Multisig.addOwner, (vm.addr(0xD4))));
    }

    // ═══════════════════════════════════════════
    //          DEADMAN SWITCH TESTS
    // ═══════════════════════════════════════════

    function test_deadman_createWithCalls() public {
        (address[] memory t, uint256[] memory v, bytes[] memory d) =
            _callArrays(POST_GUARD, abi.encodeCall(DeadmanSwitch.configure, (beneficiary, 30 days)));

        vm.deal(address(this), 5 ether);
        Multisig w = Multisig(
            payable(factory.createWithCalls{value: 5 ether}(_sortedOwners(), 0, 2, POST_GUARD, nextSalt++, t, v, d))
        );

        (address ben, uint256 timeout,) = DeadmanSwitch(POST_GUARD).configs(address(w));
        assertEq(ben, beneficiary);
        assertEq(timeout, 30 days);
    }

    function test_deadman_addedLater() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (POST_GUARD)));
        _exec(w, POST_GUARD, 0, abi.encodeCall(DeadmanSwitch.configure, (beneficiary, 30 days)));

        (address ben, uint256 timeout,) = DeadmanSwitch(POST_GUARD).configs(address(w));
        assertEq(ben, beneficiary);
        assertEq(timeout, 30 days);
    }

    function test_deadman_heartbeatResets() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (POST_GUARD)));
        _exec(w, POST_GUARD, 0, abi.encodeCall(DeadmanSwitch.configure, (beneficiary, 30 days)));

        vm.warp(block.timestamp + 20 days);

        // Any owner-signed execution resets the heartbeat via post-guard
        _exec(w, address(sink), 0, "");

        (,, uint256 last) = DeadmanSwitch(POST_GUARD).configs(address(w));
        assertEq(last, block.timestamp);
    }

    function test_deadman_claim() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (POST_GUARD)));
        _exec(w, POST_GUARD, 0, abi.encodeCall(DeadmanSwitch.configure, (beneficiary, 30 days)));

        vm.warp(block.timestamp + 30 days);

        vm.prank(beneficiary);
        DeadmanSwitch(POST_GUARD).claim(address(w));
        assertEq(beneficiary.balance, 5 ether);
    }

    function test_deadman_revertStillAlive() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (POST_GUARD)));
        _exec(w, POST_GUARD, 0, abi.encodeCall(DeadmanSwitch.configure, (beneficiary, 30 days)));

        vm.warp(block.timestamp + 15 days);

        vm.prank(beneficiary);
        vm.expectRevert(DeadmanSwitch.StillAlive.selector);
        DeadmanSwitch(POST_GUARD).claim(address(w));
    }

    function test_deadman_revertUnauthorizedClaim() public {
        Multisig w = _deployFunded(2, 5 ether);
        _exec(w, address(w), 0, abi.encodeCall(Multisig.setExecutor, (POST_GUARD)));
        _exec(w, POST_GUARD, 0, abi.encodeCall(DeadmanSwitch.configure, (beneficiary, 30 days)));

        vm.warp(block.timestamp + 30 days);

        vm.prank(address(0xBAD));
        vm.expectRevert(DeadmanSwitch.Unauthorized.selector);
        DeadmanSwitch(POST_GUARD).claim(address(w));
    }

    // ═══════════════════════════════════════════
    //         CREATE WITH CALLS TESTS
    // ═══════════════════════════════════════════

    function test_createWithCalls_setsExecutor() public {
        (address[] memory t, uint256[] memory v, bytes[] memory d) =
            _callArrays(address(spending), abi.encodeCall(SpendingAllowance.configure, (spender, 1 ether, 1 days)));

        Multisig w =
            Multisig(payable(factory.createWithCalls(_sortedOwners(), 0, 2, address(spending), nextSalt++, t, v, d)));

        assertEq(w.executor(), address(spending));
    }

    function test_createWithCalls_advancesNonce() public {
        (address[] memory t, uint256[] memory v, bytes[] memory d) = _callArrays2(
            address(recovery),
            abi.encodeCall(SocialRecovery.setGuardian, (guardian, true)),
            address(recovery),
            abi.encodeCall(SocialRecovery.setDelay, (1 days))
        );

        Multisig w =
            Multisig(payable(factory.createWithCalls(_sortedOwners(), 0, 2, address(recovery), nextSalt++, t, v, d)));

        // 2 config calls + 1 setExecutor call = nonce 3
        assertEq(w.nonce(), 3);
    }

    function test_createWithCalls_emptyCalls() public {
        address[] memory t = new address[](0);
        uint256[] memory v = new uint256[](0);
        bytes[] memory d = new bytes[](0);

        Multisig w = Multisig(payable(factory.createWithCalls(_sortedOwners(), 0, 2, address(0), nextSalt++, t, v, d)));

        // Only setExecutor call = nonce 1
        assertEq(w.nonce(), 1);
        assertEq(w.executor(), address(0));
        assertEq(w.threshold(), 2);
    }

    // ═══════════════════════════════════════════
    //          CANCEL MODULE TESTS
    // ═══════════════════════════════════════════

    function _deployTimelocked(uint128 threshold, uint32 _delay) internal returns (Multisig) {
        address[] memory sorted = _sortedOwners();
        return Multisig(payable(factory.create(sorted, _delay, threshold, address(cancelMod), nextSalt++)));
    }

    function _pks3() internal view returns (uint256[] memory) {
        uint256[] memory pks = new uint256[](3);
        pks[0] = pk1;
        pks[1] = pk2;
        pks[2] = pk3;
        return _sortedPKs(pks);
    }

    /// @dev Threshold owners approve cancel for a hash.
    function _cancelThreshold(Multisig w, bytes32 hash) internal {
        uint256[] memory pks = _pks2();
        for (uint256 i; i < 2; ++i) {
            vm.prank(vm.addr(pks[i]));
            cancelMod.cancel(address(w), hash);
        }
    }

    function test_cancel_thresholdCancels() public {
        Multisig w = _deployTimelocked(2, 1 days);
        vm.deal(address(w), 5 ether);

        bytes memory sigs = _sign(w, address(sink), 1 ether, "", _pks2());
        w.execute(address(sink), 1 ether, "", sigs);

        bytes32 hash = w.getTransactionHash(address(sink), 1 ether, "", 0);
        assertTrue(w.queued(hash) != 0);

        // 1 of 3 is not enough (threshold = 2)
        uint256[] memory pks = _pks3();
        vm.prank(vm.addr(pks[0]));
        cancelMod.cancel(address(w), hash);
        assertTrue(w.queued(hash) != 0);

        // 2nd owner reaches threshold — cancelled
        vm.prank(vm.addr(pks[1]));
        cancelMod.cancel(address(w), hash);
        assertEq(w.queued(hash), 0);
    }

    function test_cancel_createWithCalls() public {
        (address[] memory t, uint256[] memory v, bytes[] memory d) = _callArrays(address(sink), "");

        Multisig w = Multisig(
            payable(factory.createWithCalls(_sortedOwners(), 1 days, 2, address(cancelMod), nextSalt++, t, v, d))
        );

        assertEq(w.executor(), address(cancelMod));

        vm.deal(address(w), 5 ether);
        bytes memory sigs = _sign(w, address(sink), 1 ether, "", _pks2());
        w.execute(address(sink), 1 ether, "", sigs);

        bytes32 hash = w.getTransactionHash(address(sink), 1 ether, "", uint32(w.nonce() - 1));
        _cancelThreshold(w, hash);
        assertEq(w.queued(hash), 0);
    }

    function test_cancel_revertNotOwner() public {
        Multisig w = _deployTimelocked(2, 1 days);

        vm.prank(address(0xBAD));
        vm.expectRevert(CancelTx.Unauthorized.selector);
        cancelMod.cancel(address(w), bytes32(uint256(1)));
    }

    function test_cancel_revertDoubleVote() public {
        Multisig w = _deployTimelocked(2, 1 days);
        vm.deal(address(w), 5 ether);

        bytes memory sigs = _sign(w, address(sink), 1 ether, "", _pks2());
        w.execute(address(sink), 1 ether, "", sigs);
        bytes32 hash = w.getTransactionHash(address(sink), 1 ether, "", 0);

        uint256[] memory pks = _pks3();
        vm.prank(vm.addr(pks[0]));
        cancelMod.cancel(address(w), hash);

        vm.prank(vm.addr(pks[0]));
        vm.expectRevert(CancelTx.Unauthorized.selector);
        cancelMod.cancel(address(w), hash);
    }

    function test_cancel_timelockStillWorks() public {
        Multisig w = _deployTimelocked(2, 1 days);
        vm.deal(address(w), 5 ether);

        bytes memory sigs = _sign(w, address(sink), 1 ether, "", _pks2());
        w.execute(address(sink), 1 ether, "", sigs);

        assertEq(address(sink).balance, 0);
        bytes32 hash = w.getTransactionHash(address(sink), 1 ether, "", 0);
        assertTrue(w.queued(hash) != 0);

        vm.warp(block.timestamp + 1 days);
        w.executeQueued(address(sink), 1 ether, "", 0);
        assertEq(address(sink).balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //          FAST FORWARD TESTS
    // ═══════════════════════════════════════════

    function _deployTimelockedWithForward() internal returns (Multisig) {
        (address[] memory t, uint256[] memory v, bytes[] memory d) =
            _callArrays(address(cancelMod), abi.encodeCall(CancelTx.enableForward, (true)));
        vm.deal(address(this), 5 ether);
        return Multisig(
            payable(factory.createWithCalls{value: 5 ether}(
                    _sortedOwners(), 1 days, 2, address(cancelMod), nextSalt++, t, v, d
                ))
        );
    }

    function test_forward_allOwnersExecute() public {
        Multisig w = _deployTimelockedWithForward();
        assertTrue(cancelMod.forwardEnabled(address(w)));

        uint256[] memory pks = _pks3();
        vm.prank(vm.addr(pks[0]));
        cancelMod.forward(address(w), address(sink), 1 ether, "");
        vm.prank(vm.addr(pks[1]));
        cancelMod.forward(address(w), address(sink), 1 ether, "");
        assertEq(address(sink).balance, 0); // not yet — 2 of 3

        vm.prank(vm.addr(pks[2]));
        cancelMod.forward(address(w), address(sink), 1 ether, "");
        assertEq(address(sink).balance, 1 ether); // executed after all 3
    }

    function test_forward_revertNotEnabled() public {
        Multisig w = _deployTimelocked(2, 1 days);
        vm.deal(address(w), 5 ether);

        uint256[] memory pks = _pks3();
        vm.prank(vm.addr(pks[0]));
        vm.expectRevert(CancelTx.Unauthorized.selector);
        cancelMod.forward(address(w), address(sink), 1 ether, "");
    }

    function test_forward_revertNotOwner() public {
        Multisig w = _deployTimelockedWithForward();

        vm.prank(address(0xBAD));
        vm.expectRevert(CancelTx.Unauthorized.selector);
        cancelMod.forward(address(w), address(sink), 1 ether, "");
    }

    function test_forward_revertDoubleVote() public {
        Multisig w = _deployTimelockedWithForward();

        uint256[] memory pks = _pks3();
        vm.prank(vm.addr(pks[0]));
        cancelMod.forward(address(w), address(sink), 1 ether, "");

        vm.prank(vm.addr(pks[0]));
        vm.expectRevert(CancelTx.Unauthorized.selector);
        cancelMod.forward(address(w), address(sink), 1 ether, "");
    }
}
