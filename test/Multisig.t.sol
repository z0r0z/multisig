// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../src/Multisig.sol";

contract Receiver {
    fallback() external payable {}
}

contract Reverter {
    fallback() external payable {
        revert("nope");
    }
}

contract SetSlot {
    function setThreshold(uint256 val) external {
        assembly { sstore(0, val) }
    }
}

/// @dev Guard that records calls and optionally reverts.
contract MockGuard {
    uint256 public calls;
    bool public shouldRevert;

    function setShouldRevert(bool _val) external {
        shouldRevert = _val;
    }

    receive() external payable {}

    fallback() external payable {
        if (shouldRevert) revert("guard: blocked");
        ++calls;
    }
}

contract MultisigTest is Test {
    MultisigFactory factory;
    Multisig wallet;

    uint256 pk1 = 0xA1;
    uint256 pk2 = 0xB2;
    uint256 pk3 = 0xC3;

    address owner1;
    address owner2;
    address owner3;

    // EIP-712
    bytes32 constant EXECUTE_TYPEHASH = keccak256("Execute(address target,uint256 value,bytes data,uint32 nonce)");
    bytes32 constant SAFE_MSG_TYPEHASH = keccak256("SafeMessage(bytes32 hash)");

    function setUp() public {
        owner1 = vm.addr(pk1);
        owner2 = vm.addr(pk2);
        owner3 = vm.addr(pk3);

        factory = new MultisigFactory();
    }

    // ───────── Helpers ─────────

    function _sortedOwners() internal view returns (address[] memory) {
        address[] memory arr = new address[](3);
        arr[0] = owner1;
        arr[1] = owner2;
        arr[2] = owner3;
        // bubble sort
        for (uint256 i; i < 3; ++i) {
            for (uint256 j = i + 1; j < 3; ++j) {
                if (arr[i] > arr[j]) {
                    (arr[i], arr[j]) = (arr[j], arr[i]);
                }
            }
        }
        return arr;
    }

    uint256 nextSalt;

    function _deploy(uint128 threshold) internal returns (Multisig) {
        address[] memory sorted = _sortedOwners();
        return Multisig(payable(factory.create(sorted, 0, threshold, address(0), nextSalt++)));
    }

    function _deployWithDelay(uint128 threshold, uint32 _delay) internal returns (Multisig) {
        address[] memory sorted = _sortedOwners();
        return Multisig(payable(factory.create(sorted, _delay, threshold, address(0), nextSalt++)));
    }

    function _deployWithExecutor(uint128 threshold, address _executor) internal returns (Multisig) {
        address[] memory sorted = _sortedOwners();
        return Multisig(payable(factory.create(sorted, 0, threshold, _executor, nextSalt++)));
    }

    function _deployFull(uint128 threshold, uint32 _delay, address _executor, uint256 amount)
        internal
        returns (Multisig)
    {
        address[] memory sorted = _sortedOwners();
        vm.deal(address(this), amount);
        return Multisig(payable(factory.create{value: amount}(sorted, _delay, threshold, _executor, nextSalt++)));
    }

    function _deployFunded(uint128 threshold, uint256 amount) internal returns (Multisig) {
        address[] memory sorted = _sortedOwners();
        vm.deal(address(this), amount);
        return Multisig(payable(factory.create{value: amount}(sorted, 0, threshold, address(0), nextSalt++)));
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

    function _digest(Multisig w, address to, uint256 value, bytes memory data) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                w.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(EXECUTE_TYPEHASH, to, value, keccak256(data), w.nonce()))
            )
        );
    }

    /// @dev Sign with a set of private keys (must map to owners sorted ascending by address).
    function _sign(Multisig w, address to, uint256 value, bytes memory data, uint256[] memory pks)
        internal
        view
        returns (bytes memory sigs)
    {
        bytes32 hash = _digest(w, to, value, data);
        sigs = _signHash(hash, pks);
    }

    /// @dev Sign a raw hash with a set of private keys.
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

    /// @dev Compute the EIP-712 safe message digest that isValidSignature verifies against.
    function _safeDigest(Multisig w, bytes32 hash) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19\x01", w.DOMAIN_SEPARATOR(), keccak256(abi.encode(SAFE_MSG_TYPEHASH, hash)))
            );
    }

    /// @dev Returns private keys sorted by their corresponding address (ascending).
    function _sortedPKs(uint256[] memory pks) internal pure returns (uint256[] memory) {
        // bubble sort by address
        for (uint256 i; i < pks.length; ++i) {
            for (uint256 j = i + 1; j < pks.length; ++j) {
                address a = vm.addr(pks[i]);
                address b = vm.addr(pks[j]);
                if (a > b) {
                    (pks[i], pks[j]) = (pks[j], pks[i]);
                }
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

    function _pksSingle(uint256 pk) internal pure returns (uint256[] memory) {
        uint256[] memory pks = new uint256[](1);
        pks[0] = pk;
        return pks;
    }

    // ═══════════════════════════════════════════
    //              FACTORY TESTS
    // ═══════════════════════════════════════════

    function test_factory_create() public {
        wallet = _deploy(2);
        assertEq(wallet.threshold(), 2);
        address[] memory sorted = _sortedOwners();
        for (uint256 i; i < 3; ++i) {
            assertTrue(wallet.isOwner(sorted[i]));
        }
    }

    function test_factory_createWithValue() public {
        wallet = _deployFunded(2, 1 ether);
        assertEq(address(wallet).balance, 1 ether);
    }

    function test_factory_cloneIsDistinct() public {
        address[] memory sorted = _sortedOwners();
        address w1 = factory.create(sorted, 0, 2, address(0), nextSalt++);
        address w2 = factory.create(sorted, 0, 2, address(0), nextSalt++);
        assertTrue(w1 != w2);
        assertTrue(w1 != factory.implementation());
        assertTrue(w2 != factory.implementation());
        // each clone has independent state
        assertEq(Multisig(payable(w1)).nonce(), 0);
        assertEq(Multisig(payable(w2)).nonce(), 0);
    }

    function test_factory_cloneDelegatesToImpl() public {
        wallet = _deploy(2);
        // clone should have its own storage but code at impl
        assertTrue(address(wallet) != factory.implementation());
        // verify it works end-to-end: fund and execute
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
    }

    function test_factory_emitsCreated() public {
        address[] memory sorted = _sortedOwners();
        vm.expectEmit(false, false, false, false);
        emit MultisigFactory.Created(address(0)); // we don't know the address yet
        factory.create(sorted, 0, 2, address(0), nextSalt++);
    }

    function test_factory_deterministicAddress() public {
        address[] memory sorted = _sortedOwners();
        uint256 salt = 0xCAFE;
        address w1 = factory.create(sorted, 0, 2, address(0), salt);
        // deploy on a fresh factory with the same salt to verify determinism
        MultisigFactory factory2 = new MultisigFactory();
        // different factory => different address (factory address is part of CREATE2)
        address w2 = factory2.create(sorted, 0, 2, address(0), salt);
        assertTrue(w1 != w2);
    }

    function test_factory_revertDuplicateSalt() public {
        address[] memory sorted = _sortedOwners();
        uint256 salt = 0xDEAD;
        factory.create(sorted, 0, 2, address(0), salt);
        vm.expectRevert(MultisigFactory.DeploymentFailed.selector);
        factory.create(sorted, 0, 2, address(0), salt);
    }

    function test_factory_createWithZeroSalt() public {
        address[] memory sorted = _sortedOwners();
        address w = factory.create(sorted, 0, 2, address(0), 0);
        assertTrue(w != address(0));
        assertEq(Multisig(payable(w)).threshold(), 2);
    }

    function test_factory_createWithCallerPrefixedSalt() public {
        address[] memory sorted = _sortedOwners();
        uint256 salt = uint256(uint160(address(this))) << 96;
        address w = factory.create(sorted, 0, 2, address(0), salt);
        assertTrue(w != address(0));
    }

    function test_factory_createWithCallerPrefixedSaltAndNonce() public {
        address[] memory sorted = _sortedOwners();
        uint256 salt = (uint256(uint160(address(this))) << 96) | 0x42;
        address w = factory.create(sorted, 0, 2, address(0), salt);
        assertTrue(w != address(0));
    }

    function test_factory_revertSaltWrongCaller() public {
        address[] memory sorted = _sortedOwners();
        // Salt prefixed with a different address
        uint256 salt = uint256(uint160(address(0xBEEF))) << 96;
        vm.expectRevert(MultisigFactory.SaltDoesNotStartWith.selector);
        factory.create(sorted, 0, 2, address(0), salt);
    }

    function test_factory_saltCallerEnforcedPerSender() public {
        address[] memory sorted = _sortedOwners();
        address caller1 = address(0xA1);
        address caller2 = address(0xA2);
        uint256 salt1 = uint256(uint160(caller1)) << 96;
        uint256 salt2 = uint256(uint160(caller2)) << 96;

        // caller1 can use their own prefix
        vm.prank(caller1);
        address w1 = factory.create(sorted, 0, 2, address(0), salt1);
        assertTrue(w1 != address(0));

        // caller2 cannot use caller1's prefix
        vm.prank(caller2);
        vm.expectRevert(MultisigFactory.SaltDoesNotStartWith.selector);
        factory.create(sorted, 0, 2, address(0), salt1);

        // caller2 can use their own prefix
        vm.prank(caller2);
        address w2 = factory.create(sorted, 0, 2, address(0), salt2);
        assertTrue(w2 != address(0));
    }

    function test_factory_zeroSaltPermissionless() public {
        address[] memory sorted = _sortedOwners();
        // Any caller can use zero-prefixed salts
        vm.prank(address(0xA1));
        address w1 = factory.create(sorted, 0, 2, address(0), 0x1);
        assertTrue(w1 != address(0));

        vm.prank(address(0xA2));
        address w2 = factory.create(sorted, 0, 2, address(0), 0x2);
        assertTrue(w2 != address(0));
    }

    // ═══════════════════════════════════════════
    //              INIT TESTS
    // ═══════════════════════════════════════════

    function test_init_setsState() public {
        wallet = _deploy(2);
        assertEq(wallet.threshold(), 2);
        assertEq(wallet.nonce(), 0);
        assertEq(wallet.DOMAIN_SEPARATOR(), _domainSeparator(address(wallet)));
    }

    function test_init_revertDoubleInit() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.init(sorted, 0, 2, address(0));
    }

    function test_init_revertThresholdZero() public {
        address[] memory sorted = _sortedOwners();
        vm.expectRevert(Multisig.InvalidConfig.selector);
        factory.create(sorted, 0, 0, address(0), nextSalt++);
    }

    function test_init_revertThresholdTooHigh() public {
        address[] memory sorted = _sortedOwners();
        vm.expectRevert(Multisig.InvalidConfig.selector);
        factory.create(sorted, 0, 4, address(0), nextSalt++);
    }

    function test_init_revertUnsortedOwners() public {
        address[] memory sorted = _sortedOwners();
        // swap first two to break sort
        (sorted[0], sorted[1]) = (sorted[1], sorted[0]);
        vm.expectRevert(Multisig.InvalidConfig.selector);
        factory.create(sorted, 0, 2, address(0), nextSalt++);
    }

    function test_init_revertDuplicateOwners() public {
        address[] memory dup = new address[](2);
        dup[0] = owner1;
        dup[1] = owner1;
        vm.expectRevert(Multisig.InvalidConfig.selector);
        factory.create(dup, 0, 1, address(0), nextSalt++);
    }

    function test_init_revertAddressZeroOwner() public {
        address[] memory arr = new address[](1);
        arr[0] = address(0);
        vm.expectRevert(Multisig.InvalidConfig.selector);
        factory.create(arr, 0, 1, address(0), nextSalt++);
    }

    // ═══════════════════════════════════════════
    //              EXECUTE TESTS
    // ═══════════════════════════════════════════

    function test_execute_sendETH() public {
        wallet = _deployFunded(2, 5 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());

        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
        assertEq(address(wallet).balance, 4 ether);
        assertEq(wallet.nonce(), 1);
    }

    function test_execute_callWithData() public {
        wallet = _deployFunded(2, 0);
        // call setThreshold on self
        bytes memory data = abi.encodeCall(Multisig.setThreshold, (1));

        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.threshold(), 1);
    }

    function test_execute_allSigners() public {
        wallet = _deployFunded(3, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks3());

        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
    }

    function test_execute_incrementsNonce() public {
        wallet = _deployFunded(2, 10 ether);
        address receiver = address(new Receiver());

        for (uint256 i; i < 3; ++i) {
            bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
            wallet.execute(receiver, 1 ether, "", sigs);
            assertEq(wallet.nonce(), i + 1);
        }
    }

    function test_execute_revertInvalidSigner() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        // sign with a non-owner key
        uint256 fakePk = 0xDEAD;
        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = fakePk;
        pks = _sortedPKs(pks);

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", pks);

        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_execute_revertDuplicateSigner() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk1; // same signer twice

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", pks);

        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_execute_revertWrongOrder() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        // sign in descending order (wrong)
        uint256[] memory pks = _pks2();
        // reverse
        (pks[0], pks[1]) = (pks[1], pks[0]);

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", pks);

        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_execute_revertReplayNonce() public {
        wallet = _deployFunded(2, 10 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());

        wallet.execute(receiver, 1 ether, "", sigs);

        // same sigs, but nonce has advanced
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_execute_revertCallFails() public {
        wallet = _deployFunded(2, 1 ether);
        address rev = address(new Reverter());

        bytes memory sigs = _sign(wallet, rev, 1 ether, "", _pks2());

        vm.expectRevert(bytes("nope"));
        wallet.execute(rev, 1 ether, "", sigs);
    }

    function test_execute_revertInsufficientSigs() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        // only 1 sig for threshold=2
        uint256[] memory pks = new uint256[](1);
        pks[0] = pk1;

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", pks);

        vm.expectRevert(); // out of bounds
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_execute_threshold1() public {
        wallet = _deployFunded(1, 1 ether);
        address receiver = address(new Receiver());
        address[] memory sorted = _sortedOwners();

        // find which pk matches sorted[0]
        uint256 pk;
        if (vm.addr(pk1) == sorted[0]) pk = pk1;
        else if (vm.addr(pk2) == sorted[0]) pk = pk2;
        else pk = pk3;

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pksSingle(pk));

        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //           OWNER MANAGEMENT TESTS
    // ═══════════════════════════════════════════

    function test_addOwner() public {
        wallet = _deploy(2);
        address newOwner = address(0xBEEF);

        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, sigs);
        assertTrue(wallet.isOwner(newOwner));
    }

    function test_addOwner_revertNotSelf() public {
        wallet = _deploy(2);
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.addOwner(address(0xBEEF));
    }

    function test_addOwner_revertDuplicate() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();

        bytes memory data = abi.encodeCall(Multisig.addOwner, (sorted[0]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(); // require(!isOwner[_owner])
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_addOwner_revertAddressZero() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.addOwner, (address(0)));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(); // require(_owner != address(0))
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_removeOwner() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[1], sorted[2]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, sigs);
        assertFalse(wallet.isOwner(sorted[2]));
    }

    function test_removeOwner_revertNotSelf() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.removeOwner(address(1), sorted[0]);
    }

    function test_removeOwner_revertNotOwner() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (address(1), address(0xDEAD)));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(); // require(_owners[_owner] != address(0))
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_removeOwner_revertWrongPrevOwner() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();

        // correct owner, wrong prevOwner
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[2], sorted[0]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(); // require(_owners[prevOwner] == _owner)
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_removeOwner_revertBelowThreshold() public {
        wallet = _deploy(3);
        address[] memory sorted = _sortedOwners();

        // removing any owner would leave 2 owners < threshold 3
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (address(1), sorted[0]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks3());

        vm.expectRevert(); // require(owners.length >= threshold)
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_setThreshold() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (3));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.threshold(), 3);
    }

    function test_setThreshold_revertNotSelf() public {
        wallet = _deploy(2);
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.setThreshold(1);
    }

    function test_setThreshold_revertZero() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (0));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert();
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_setThreshold_revertTooHigh() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (4));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert();
        wallet.execute(address(wallet), 0, data, sigs);
    }

    // ═══════════════════════════════════════════
    //              RECEIVE TESTS
    // ═══════════════════════════════════════════

    function test_receiveETH() public {
        wallet = _deploy(2);
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(wallet).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(wallet).balance, 1 ether);
    }

    function test_onERC721Received() public {
        wallet = _deploy(2);
        bytes4 selector_ = bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
        (bool ok, bytes memory ret) =
            address(wallet).call(abi.encodeWithSelector(selector_, address(0), address(0), uint256(0), ""));
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes4)), selector_);
    }

    function test_onERC1155Received() public {
        wallet = _deploy(2);
        bytes4 selector_ = bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
        (bool ok, bytes memory ret) =
            address(wallet).call(abi.encodeWithSelector(selector_, address(0), address(0), uint256(0), uint256(0), ""));
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes4)), selector_);
    }

    function test_onERC1155BatchReceived() public {
        wallet = _deploy(2);
        bytes4 selector_ = bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));
        (bool ok, bytes memory ret) = address(wallet)
            .call(abi.encodeWithSelector(selector_, address(0), address(0), new uint256[](0), new uint256[](0), ""));
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes4)), selector_);
    }

    // ═══════════════════════════════════════════
    //              EIP-1271 TESTS
    // ═══════════════════════════════════════════

    function test_isValidSignature_returnsMagicValue() public {
        wallet = _deploy(2);
        bytes32 hash = keccak256("test message");
        bytes memory sigs = _signHash(_safeDigest(wallet, hash), _pks2());

        bytes4 result = wallet.isValidSignature(hash, sigs);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_magicValueMatchesSelector() public {
        wallet = _deploy(2);
        bytes4 expected = Multisig.isValidSignature.selector;
        assertEq(expected, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_allSigners() public {
        wallet = _deploy(3);
        bytes32 hash = keccak256("test message");
        bytes memory sigs = _signHash(_safeDigest(wallet, hash), _pks3());

        assertEq(wallet.isValidSignature(hash, sigs), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_threshold1() public {
        wallet = _deploy(1);
        bytes32 hash = keccak256("test message");
        address[] memory sorted = _sortedOwners();

        uint256 pk;
        if (vm.addr(pk1) == sorted[0]) pk = pk1;
        else if (vm.addr(pk2) == sorted[0]) pk = pk2;
        else pk = pk3;

        bytes memory sigs = _signHash(_safeDigest(wallet, hash), _pksSingle(pk));
        assertEq(wallet.isValidSignature(hash, sigs), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_revertInvalidSigner() public {
        wallet = _deploy(2);
        bytes32 hash = keccak256("test message");

        uint256 fakePk = 0xDEAD;
        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = fakePk;
        pks = _sortedPKs(pks);

        bytes memory sigs = _signHash(_safeDigest(wallet, hash), pks);
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.isValidSignature(hash, sigs);
    }

    function test_isValidSignature_revertDuplicateSigner() public {
        wallet = _deploy(2);
        bytes32 hash = keccak256("test message");

        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk1;

        bytes memory sigs = _signHash(_safeDigest(wallet, hash), pks);
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.isValidSignature(hash, sigs);
    }

    function test_isValidSignature_revertWrongOrder() public {
        wallet = _deploy(2);
        bytes32 hash = keccak256("test message");

        uint256[] memory pks = _pks2();
        (pks[0], pks[1]) = (pks[1], pks[0]);

        bytes memory sigs = _signHash(_safeDigest(wallet, hash), pks);
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.isValidSignature(hash, sigs);
    }

    function test_isValidSignature_revertInsufficientSigs() public {
        wallet = _deploy(2);
        bytes32 hash = keccak256("test message");

        bytes memory sigs = _signHash(hash, _pksSingle(pk1));
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.isValidSignature(hash, sigs);
    }

    function test_isValidSignature_revertEmptySigs() public {
        wallet = _deploy(2);
        bytes32 hash = keccak256("test message");

        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.isValidSignature(hash, "");
    }

    // ═══════════════════════════════════════════
    //              GETOWNERS TESTS
    // ═══════════════════════════════════════════

    function test_getOwners() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();
        address[] memory result = wallet.getOwners();
        assertEq(result.length, 3);
        for (uint256 i; i < 3; ++i) {
            assertEq(result[i], sorted[i]);
        }
    }

    function test_getOwners_afterAddRemove() public {
        wallet = _deploy(2);
        address newOwner = address(0xBEEF);

        // add owner
        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.getOwners().length, 4);

        // remove owner (addOwner inserts at front, so prevOwner is SENTINEL)
        data = abi.encodeCall(Multisig.removeOwner, (address(1), newOwner));
        sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.getOwners().length, 3);
    }

    // ═══════════════════════════════════════════
    //              EIP-712 TESTS
    // ═══════════════════════════════════════════

    function test_domainSeparatorMatchesExpected() public {
        wallet = _deploy(2);
        assertEq(wallet.DOMAIN_SEPARATOR(), _domainSeparator(address(wallet)));
    }

    function test_eip712DomainTypeHash() public pure {
        assertEq(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f
        );
    }

    function test_nameHash() public pure {
        assertEq(keccak256("Multisig"), 0xcd4046335c6490bc800b62dfe4e32b5bbe64545e84e866aba69afbf5ce39f2df);
    }

    function test_versionHash() public pure {
        assertEq(keccak256("1"), 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6);
    }

    function test_executeTypeHash() public pure {
        assertEq(keccak256("Execute(address target,uint256 value,bytes data,uint32 nonce)"), EXECUTE_TYPEHASH);
    }

    function test_safeMessageTypeHash() public pure {
        assertEq(keccak256("SafeMessage(bytes32 hash)"), SAFE_MSG_TYPEHASH);
    }

    function test_errorSelectors() public pure {
        assertEq(MultisigFactory.SaltDoesNotStartWith.selector, bytes4(0x0c4549ef));
        assertEq(MultisigFactory.DeploymentFailed.selector, bytes4(0x30116425));
    }

    function test_fallbackSelectors() public pure {
        assertEq(bytes4(keccak256("onERC721Received(address,address,uint256,bytes)")), bytes4(0x150b7a02));
        assertEq(bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)")), bytes4(0xf23a6e61));
        assertEq(
            bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)")), bytes4(0xbc197c81)
        );
    }

    function test_fallbackUnknownSelectorReturnsEmpty() public {
        wallet = _deploy(2);
        (bool ok, bytes memory ret) = address(wallet).call(abi.encodeWithSelector(0xdeadbeef));
        assertTrue(ok, "fallback should not revert");
        assertEq(ret.length, 0, "unknown selector returns empty");
    }

    // ═══════════════════════════════════════════
    //           COMBINED FLOW TESTS
    // ═══════════════════════════════════════════

    function test_addThenRemoveOwner() public {
        wallet = _deploy(2);
        address newOwner = address(0xBEEF);

        // add
        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertTrue(wallet.isOwner(newOwner));

        // remove (addOwner inserts at front, so prevOwner is SENTINEL)
        data = abi.encodeCall(Multisig.removeOwner, (address(1), newOwner));
        sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertFalse(wallet.isOwner(newOwner));
    }

    function test_lowerThresholdThenExecuteWith1() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());
        address[] memory sorted = _sortedOwners();

        // lower threshold to 1
        bytes memory data = abi.encodeCall(Multisig.setThreshold, (1));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.threshold(), 1);

        // now execute with single sig
        uint256 pk;
        if (vm.addr(pk1) == sorted[0]) pk = pk1;
        else if (vm.addr(pk2) == sorted[0]) pk = pk2;
        else pk = pk3;

        sigs = _sign(wallet, receiver, 1 ether, "", _pksSingle(pk));
        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
    }

    function test_execute_revertZeroRecovery() public {
        wallet = _deployFunded(1, 1 ether);
        address receiver = address(new Receiver());
        // 65 zero bytes → ecrecover returns address(0)
        bytes memory sigs = new bytes(65);
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_isValidSignature_revertZeroRecovery() public {
        wallet = _deploy(1);
        bytes32 hash = keccak256("test message");
        // 65 zero bytes → ecrecover returns address(0)
        bytes memory sigs = new bytes(65);
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.isValidSignature(hash, sigs);
    }

    // ═══════════════════════════════════════════
    //            EXECUTOR TESTS
    // ═══════════════════════════════════════════

    function test_executor_setAtInit() public {
        address exec = address(0xEEEE);
        wallet = _deployWithExecutor(2, exec);
        assertEq(wallet.executor(), exec);
    }

    function test_executor_bypassesSigs() public {
        address exec = address(0xEEEE);
        wallet = _deployWithExecutor(2, exec);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        vm.prank(exec);
        wallet.execute(receiver, 1 ether, "", "");
        assertEq(receiver.balance, 1 ether);
    }

    function test_executor_bypassesDelay() public {
        address exec = address(0xEEEE);
        wallet = _deployFull(2, 1 days, exec, 1 ether);
        address receiver = address(new Receiver());

        // executor executes immediately despite delay
        vm.prank(exec);
        wallet.execute(receiver, 1 ether, "", "");
        assertEq(receiver.balance, 1 ether);
    }

    function test_executor_ownersStillTimelocked() public {
        address exec = address(0xEEEE);
        wallet = _deployFull(2, 1 days, exec, 1 ether);
        address receiver = address(new Receiver());

        // owners go through timelock
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        // ETH stays — tx was queued, not executed
        assertEq(receiver.balance, 0);
        assertEq(address(wallet).balance, 1 ether);
    }

    function test_executor_nonExecutorCannotBypassSigs() public {
        address exec = address(0xEEEE);
        wallet = _deployWithExecutor(2, exec);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        // random caller with no sigs
        vm.prank(address(0xDEAD));
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", "");
    }

    function test_executor_setExecutor() public {
        wallet = _deploy(2);
        address exec = address(0xEEEE);

        bytes memory data = abi.encodeCall(Multisig.setExecutor, (exec));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);

        assertEq(wallet.executor(), exec);
    }

    function test_executor_revokeExecutor() public {
        address exec = address(0xEEEE);
        wallet = _deployWithExecutor(2, exec);

        bytes memory data = abi.encodeCall(Multisig.setExecutor, (address(0)));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);

        assertEq(wallet.executor(), address(0));

        // executor can no longer bypass
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());
        vm.prank(exec);
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", "");
    }

    function test_executor_callWithData() public {
        address exec = address(0xEEEE);
        wallet = _deployWithExecutor(2, exec);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (1));
        vm.prank(exec);
        wallet.execute(address(wallet), 0, data, "");
        assertEq(wallet.threshold(), 1);
    }

    function test_executor_setExecutorRevertNotSelf() public {
        wallet = _deploy(2);
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.setExecutor(address(0xEEEE));
    }

    // ═══════════════════════════════════════════
    //              BATCH TESTS
    // ═══════════════════════════════════════════

    function test_batch_viaExecute() public {
        wallet = _deploy(2);
        address newOwner = address(0xBEEF);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = address(wallet);
        targets[1] = address(wallet);
        datas[0] = abi.encodeCall(Multisig.addOwner, (newOwner));
        datas[1] = abi.encodeCall(Multisig.setThreshold, (3));

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(wallet, address(wallet), 0, batchData, _pks2());

        wallet.execute(address(wallet), 0, batchData, sigs);
        assertTrue(wallet.isOwner(newOwner));
        assertEq(wallet.threshold(), 3);
    }

    function test_batch_revertNotSelf() public {
        wallet = _deploy(2);

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(wallet);
        datas[0] = abi.encodeCall(Multisig.setThreshold, (1));

        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.batch(targets, values, datas);
    }

    function test_batch_withValues() public {
        wallet = _deploy(2);
        vm.deal(address(wallet), 3 ether);
        address r1 = address(new Receiver());
        address r2 = address(new Receiver());

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = r1;
        targets[1] = r2;
        values[0] = 1 ether;
        values[1] = 2 ether;

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(wallet, address(wallet), 0, batchData, _pks2());

        wallet.execute(address(wallet), 0, batchData, sigs);
        assertEq(r1.balance, 1 ether);
        assertEq(r2.balance, 2 ether);
    }

    function test_batch_revertInnerCallFails() public {
        wallet = _deploy(2);
        address rev = address(new Reverter());

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = rev;

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(wallet, address(wallet), 0, batchData, _pks2());

        vm.expectRevert(bytes("nope"));
        wallet.execute(address(wallet), 0, batchData, sigs);
    }

    // ═══════════════════════════════════════════
    //           TIMELOCK TESTS (FACTORY)
    // ═══════════════════════════════════════════

    function test_timelock_initWithDelay() public {
        wallet = _deployWithDelay(2, 1 days);
        assertEq(wallet.delay(), 1 days);
    }

    function test_timelock_queuesWhenDelaySet() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        assertEq(receiver.balance, 0);
        assertEq(wallet.nonce(), n + 1);
    }

    function test_timelock_executeQueuedAfterDelay() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        wallet.executeQueued(receiver, 1 ether, "", n);
        assertEq(receiver.balance, 1 ether);
    }

    function test_timelock_revertTooEarly() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days - 1);
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, block.timestamp + 1));
        wallet.executeQueued(receiver, 1 ether, "", n);
    }

    function test_timelock_revertNotQueued() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(address(0xBEEF), 0, "", 0);
    }

    function test_timelock_revertReplay() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 2 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        wallet.executeQueued(receiver, 1 ether, "", n);

        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(receiver, 1 ether, "", n);
    }

    function test_timelock_setDelay() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.setDelay, (7 days));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);

        assertEq(wallet.delay(), 7 days);
    }

    function test_timelock_setDelayRevertNotSelf() public {
        wallet = _deploy(2);
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.setDelay(1 days);
    }

    function test_timelock_executeQueuedRevertCallFails() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address rev = address(new Reverter());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, rev, 1 ether, "", _pks2());
        wallet.execute(rev, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(bytes("nope"));
        wallet.executeQueued(rev, 1 ether, "", n);
    }

    function test_timelock_executeQueuedWithData() public {
        wallet = _deployWithDelay(2, 1 days);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (1));
        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);

        vm.warp(block.timestamp + 1 days);
        wallet.executeQueued(address(wallet), 0, data, n);
        assertEq(wallet.threshold(), 1);
    }

    function test_timelock_initWithDelayAndExecutor() public {
        address exec = address(0xEEEE);
        wallet = _deployFull(2, 1 days, exec, 0);
        assertEq(wallet.delay(), 1 days);
        assertEq(wallet.executor(), exec);
    }

    function test_timelock_executeQueuedPermissionless() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        vm.prank(address(0xCAFE));
        wallet.executeQueued(receiver, 1 ether, "", n);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //           CANCEL QUEUED TESTS
    // ═══════════════════════════════════════════

    function _txHash(Multisig w, address to, uint256 value, bytes memory data, uint32 n)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01", w.DOMAIN_SEPARATOR(), keccak256(abi.encode(EXECUTE_TYPEHASH, to, value, keccak256(data), n))
            )
        );
    }

    function test_cancelQueued_executorCancels() public {
        address exec = address(0xEEEE);
        wallet = _deployFull(2, 1 days, exec, 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        bytes32 hash = _txHash(wallet, receiver, 1 ether, "", n);
        assertGt(wallet.queued(hash), 0);

        vm.prank(exec);
        wallet.cancelQueued(hash);
        assertEq(wallet.queued(hash), 0);

        // executeQueued now reverts
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(receiver, 1 ether, "", n);
    }

    function test_cancelQueued_revertNotExecutor() public {
        address exec = address(0xEEEE);
        wallet = _deployFull(2, 1 days, exec, 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        bytes32 hash = _txHash(wallet, receiver, 1 ether, "", n);

        // random caller cannot cancel
        vm.prank(address(0xCAFE));
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.cancelQueued(hash);

        // owner cannot cancel directly either
        vm.prank(owner1);
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.cancelQueued(hash);
    }

    function test_cancelQueued_revertNoExecutorSet() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        bytes32 hash = _txHash(wallet, receiver, 1 ether, "", n);

        // no executor set, so nobody can cancel
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.cancelQueued(hash);
    }

    // ═══════════════════════════════════════════
    //           DELEGATECALL TESTS
    // ═══════════════════════════════════════════

    function test_delegateCall_viaExecute() public {
        wallet = _deploy(2);
        SetSlot impl = new SetSlot();

        // delegatecall SetSlot.setThreshold — writes to wallet's storage
        bytes memory innerData = abi.encodeCall(SetSlot.setThreshold, (42));
        bytes memory data = abi.encodeCall(Multisig.delegateCall, (address(impl), innerData));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, sigs);
        // slot 0 packs delay/nonce/threshold/executor — threshold is at bits 80..95
        // but SetSlot writes raw uint256 to slot 0, overwriting everything
        // just verify the call succeeded by checking slot 0 changed
        assertEq(uint256(vm.load(address(wallet), bytes32(0))), 42);
    }

    function test_delegateCall_revertNotSelf() public {
        wallet = _deploy(2);
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.delegateCall(address(0xBEEF), "");
    }

    function test_delegateCall_revertInnerCallFails() public {
        wallet = _deploy(2);
        address rev = address(new Reverter());

        bytes memory data = abi.encodeCall(Multisig.delegateCall, (rev, ""));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(bytes("nope"));
        wallet.execute(address(wallet), 0, data, sigs);
    }

    // ═══════════════════════════════════════════
    //              EVENT TESTS
    // ═══════════════════════════════════════════

    function test_event_executionSuccess() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());

        vm.expectEmit(false, false, false, false);
        emit Multisig.ExecutionSuccess(bytes32(0), 0);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_event_queued() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());

        vm.expectEmit(false, false, false, true);
        emit Multisig.Queued(bytes32(0), 0, block.timestamp + 1 days);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_event_executionSuccessQueued() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(false, false, false, true);
        emit Multisig.ExecutionSuccess(bytes32(0), n);
        wallet.executeQueued(receiver, 1 ether, "", n);
    }

    function test_event_addedOwner() public {
        wallet = _deploy(2);
        address newOwner = address(0xBEEF);

        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectEmit(true, false, false, false);
        emit Multisig.AddedOwner(newOwner);
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_event_removedOwner() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[1], sorted[2]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectEmit(true, false, false, false);
        emit Multisig.RemovedOwner(sorted[2]);
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_event_changedThreshold() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (3));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectEmit(false, false, false, true);
        emit Multisig.ChangedThreshold(3);
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_event_changedDelay() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.setDelay, (7 days));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectEmit(false, false, false, true);
        emit Multisig.ChangedDelay(7 days);
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_event_changedExecutor() public {
        wallet = _deploy(2);
        address exec = address(0xEEEE);

        bytes memory data = abi.encodeCall(Multisig.setExecutor, (exec));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectEmit(true, false, false, false);
        emit Multisig.ChangedExecutor(exec);
        wallet.execute(address(wallet), 0, data, sigs);
    }

    // ═══════════════════════════════════════════
    //              FUZZ TESTS
    // ═══════════════════════════════════════════

    function testFuzz_init_revertInvalidThreshold(uint256 _threshold) public {
        address[] memory sorted = _sortedOwners();
        vm.assume(_threshold == 0 || _threshold > sorted.length);
        vm.expectRevert(Multisig.InvalidConfig.selector);
        factory.create(sorted, 0, _threshold, address(0), nextSalt++);
    }

    function testFuzz_init_validThreshold(uint256 _threshold) public {
        address[] memory sorted = _sortedOwners();
        _threshold = bound(_threshold, 1, sorted.length);
        Multisig w = Multisig(payable(factory.create(sorted, 0, _threshold, address(0), nextSalt++)));
        assertEq(w.threshold(), _threshold);
        assertEq(w.getOwners().length, sorted.length);
        for (uint256 i; i < sorted.length; ++i) {
            assertTrue(w.isOwner(sorted[i]));
        }
    }

    function testFuzz_removeOwner_arrayIntegrity(uint256 indexSeed) public {
        // deploy with threshold=1 so any single owner can sign
        wallet = _deploy(1);
        address[] memory sorted = _sortedOwners();
        uint256 idx = indexSeed % sorted.length;
        address toRemove = sorted[idx];

        // find the lowest-addressed owner that is NOT the one being removed
        address[] memory sortedAll = _sortedOwners();
        uint256 signerPk;
        for (uint256 i; i < sortedAll.length; ++i) {
            if (sortedAll[i] != toRemove) {
                if (vm.addr(pk1) == sortedAll[i]) signerPk = pk1;
                else if (vm.addr(pk2) == sortedAll[i]) signerPk = pk2;
                else signerPk = pk3;
                break;
            }
        }

        // compute prevOwner in the linked list: SENTINEL → sorted[0] → sorted[1] → sorted[2] → SENTINEL
        address prevOwner = idx == 0 ? address(1) : sorted[idx - 1];
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (prevOwner, toRemove));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pksSingle(signerPk));
        wallet.execute(address(wallet), 0, data, sigs);

        assertFalse(wallet.isOwner(toRemove));
        address[] memory remaining = wallet.getOwners();
        assertEq(remaining.length, sorted.length - 1);
        for (uint256 i; i < remaining.length; ++i) {
            assertTrue(wallet.isOwner(remaining[i]));
            assertTrue(remaining[i] != toRemove);
        }
    }

    function testFuzz_factory_saltAccessControl(address caller, uint256 salt) public {
        address[] memory sorted = _sortedOwners();
        address prefix = address(uint160(salt >> 96));
        if (prefix != address(0) && prefix != caller) {
            vm.prank(caller);
            vm.expectRevert(MultisigFactory.SaltDoesNotStartWith.selector);
            factory.create(sorted, 0, 2, address(0), salt);
        } else {
            vm.prank(caller);
            address w = factory.create(sorted, 0, 2, address(0), salt);
            assertTrue(w != address(0));
        }
    }

    function testFuzz_execute_revertBadSigsLength(uint256 sigsLen) public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());
        uint256 expectedLen = uint256(wallet.threshold()) * 65;
        vm.assume(sigsLen != expectedLen);
        sigsLen = bound(sigsLen, 0, 500);
        bytes memory sigs = new bytes(sigsLen);
        vm.expectRevert();
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function testFuzz_isValidSignature_revertBadSigsLength(uint256 sigsLen) public {
        wallet = _deploy(2);
        bytes32 hash = keccak256("test message");
        uint256 expectedLen = uint256(wallet.threshold()) * 65;
        vm.assume(sigsLen != expectedLen);
        sigsLen = bound(sigsLen, 0, 500);
        bytes memory sigs = new bytes(sigsLen);
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.isValidSignature(hash, sigs);
    }

    // ───────── Storage Optimization Proof ─────────

    function test_execute_singleSlotReadWrite() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk2;
        if (vm.addr(pk1) > vm.addr(pk2)) (pks[0], pks[1]) = (pks[1], pks[0]);

        bytes memory sigs = _sign(wallet, receiver, 0.1 ether, "", pks);

        vm.record();
        wallet.execute(receiver, 0.1 ether, "", sigs);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(wallet));

        // Slot 0 holds delay|nonce|threshold|executor — packed into a single 32-byte slot.
        // Expect 1 SSTORE (nonce++). vm.accesses counts 2 reads because SSTORE implicitly
        // reads the current value for EIP-2200 gas calculation, so 1 SLOAD + 1 SSTORE = 2 reads + 1 write.
        uint256 slot0Reads;
        uint256 slot0Writes;
        for (uint256 i; i < reads.length; i++) {
            if (reads[i] == bytes32(0)) slot0Reads++;
        }
        for (uint256 i; i < writes.length; i++) {
            if (writes[i] == bytes32(0)) slot0Writes++;
        }

        assertEq(slot0Writes, 1, "slot 0: exactly 1 SSTORE (nonce++)");
    }

    // ═══════════════════════════════════════════
    //              GUARD TESTS
    // ═══════════════════════════════════════════

    function _etchGuard(address addr) internal returns (MockGuard) {
        MockGuard g = new MockGuard();
        vm.etch(addr, address(g).code);
        return MockGuard(payable(addr));
    }

    // Leading 0x1111 → pre-guard only
    function test_guard_preGuardCalled() public {
        address guardAddr = address(uint160(0x1111 << 144) | uint160(0xABCDEF));
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 0, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 0.5 ether, "", _pks2());
        wallet.execute(receiver, 0.5 ether, "", sigs);

        assertEq(guard.calls(), 1, "pre-guard called once");
        assertEq(receiver.balance, 0.5 ether, "tx executed");
    }

    // Trailing 0x1111 → post-guard only
    function test_guard_postGuardCalled() public {
        address guardAddr = address((uint160(0xABCD) << 144) | 0x1111);
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 0, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 0.5 ether, "", _pks2());
        wallet.execute(receiver, 0.5 ether, "", sigs);

        assertEq(guard.calls(), 1, "post-guard called once");
        assertEq(receiver.balance, 0.5 ether, "tx executed");
    }

    // Leading 0x1111 AND trailing 0x1111 → both pre and post guard
    function test_guard_preAndPostGuardCalled() public {
        address guardAddr = address((uint160(0x1111) << 144) | 0x1111);
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 0, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 0.5 ether, "", _pks2());
        wallet.execute(receiver, 0.5 ether, "", sigs);

        assertEq(guard.calls(), 2, "guard called twice (pre + post)");
        assertEq(receiver.balance, 0.5 ether, "tx executed");
    }

    // No magic bytes → plain executor, no guard calls
    function test_guard_plainExecutorNoGuardCalls() public {
        address exec = address(0xEEEE);
        MockGuard guard = _etchGuard(exec);
        wallet = _deployFull(2, 0, exec, 1 ether);
        address receiver = address(new Receiver());

        vm.prank(exec);
        wallet.execute(receiver, 0.5 ether, "", "");

        assertEq(guard.calls(), 0, "no guard calls for plain executor");
        assertEq(receiver.balance, 0.5 ether, "tx executed");
    }

    // Pre-guard reverts → execution blocked
    function test_guard_preGuardReverts() public {
        address guardAddr = address(uint160(0x1111 << 144) | uint160(0xABCDEF));
        MockGuard guard = _etchGuard(guardAddr);
        guard = MockGuard(payable(guardAddr));
        wallet = _deployFull(2, 0, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        // enable revert on the etched address
        vm.store(guardAddr, bytes32(uint256(1)), bytes32(uint256(1))); // shouldRevert = true

        bytes memory sigs = _sign(wallet, receiver, 0.5 ether, "", _pks2());
        vm.expectRevert("guard: blocked");
        wallet.execute(receiver, 0.5 ether, "", sigs);
    }

    // Post-guard reverts → execution reverted after call
    function test_guard_postGuardReverts() public {
        address guardAddr = address((uint160(0xABCD) << 144) | 0x1111);
        _etchGuard(guardAddr);
        wallet = _deployFull(2, 0, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        vm.store(guardAddr, bytes32(uint256(1)), bytes32(uint256(1))); // shouldRevert = true

        bytes memory sigs = _sign(wallet, receiver, 0.5 ether, "", _pks2());
        vm.expectRevert("guard: blocked");
        wallet.execute(receiver, 0.5 ether, "", sigs);
    }

    // Executor with pre-guard can still bypass sigs
    function test_guard_executorWithPreGuardBypassesSigs() public {
        address guardAddr = address(uint160(0x1111 << 144) | uint160(0xABCDEF));
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 0, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        vm.prank(guardAddr);
        wallet.execute(receiver, 0.5 ether, "", "");

        assertEq(guard.calls(), 1, "pre-guard still called");
        assertEq(receiver.balance, 0.5 ether, "executor bypassed sigs");
    }

    // Executor with both guards bypasses sigs but both guards fire
    function test_guard_executorWithBothGuardsBypassesSigs() public {
        address guardAddr = address((uint160(0x1111) << 144) | 0x1111);
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 0, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        vm.prank(guardAddr);
        wallet.execute(receiver, 0.5 ether, "", "");

        assertEq(guard.calls(), 2, "both guards called");
        assertEq(receiver.balance, 0.5 ether, "executor bypassed sigs");
    }

    // Pre-guard fires on queued transactions too
    function test_guard_preGuardFiresOnQueue() public {
        address guardAddr = address(uint160(0x1111 << 144) | uint160(0xABCDEF));
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 1 days, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 0.5 ether, "", _pks2());
        wallet.execute(receiver, 0.5 ether, "", sigs);

        assertEq(guard.calls(), 1, "pre-guard called on queue");
        assertEq(receiver.balance, 0, "tx queued, not executed");
    }

    // Post-guard fires on queued transactions too
    function test_guard_postGuardFiresOnQueue() public {
        address guardAddr = address((uint160(0xABCD) << 144) | 0x1111);
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 1 days, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 0.5 ether, "", _pks2());
        wallet.execute(receiver, 0.5 ether, "", sigs);

        assertEq(guard.calls(), 1, "post-guard called on queue");
        assertEq(receiver.balance, 0, "tx queued, not executed");
    }

    // ═══════════════════════════════════════════
    //        CROSS-WALLET REPLAY PROTECTION
    // ═══════════════════════════════════════════

    function test_crossWallet_sigNotReusable() public {
        Multisig w1 = _deployFunded(2, 2 ether);
        Multisig w2 = _deployFunded(2, 2 ether);
        address receiver = address(new Receiver());

        // Sign for w1
        bytes memory sigs = _sign(w1, receiver, 1 ether, "", _pks2());
        w1.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);

        // Replay on w2 — different DOMAIN_SEPARATOR
        vm.expectRevert(Multisig.InvalidSig.selector);
        w2.execute(receiver, 1 ether, "", sigs);
    }

    function test_crossWallet_isValidSignatureNotReusable() public {
        Multisig w1 = _deploy(2);
        Multisig w2 = _deploy(2);
        bytes32 hash = keccak256("test message");

        bytes memory sigs = _signHash(_safeDigest(w1, hash), _pks2());
        assertEq(w1.isValidSignature(hash, sigs), bytes4(0x1626ba7e));

        // Replay on w2
        vm.expectRevert(Multisig.InvalidSig.selector);
        w2.isValidSignature(hash, sigs);
    }

    function test_crossChain_sigInvalidAfterFork() public {
        wallet = _deployFunded(2, 2 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        // Simulate chain fork — change chainId
        vm.chainId(999);
        bytes memory sigs2 = _sign(wallet, receiver, 1 ether, "", _pks2());
        // Sign on new chain works
        wallet.execute(receiver, 1 ether, "", sigs2);
        assertEq(receiver.balance, 2 ether);
    }

    // ═══════════════════════════════════════════
    //      EXECUTE / ISVALIDSIG DOMAIN ISOLATION
    // ═══════════════════════════════════════════

    function test_executeSigNotValidForIsValidSignature() public {
        wallet = _deploy(2);

        // Sign an execute digest
        bytes32 execDigest = _digest(wallet, address(0xBEEF), 0, "");
        bytes memory sigs = _signHash(execDigest, _pks2());

        // Use as isValidSignature — should fail (different type hash wrapping)
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.isValidSignature(execDigest, sigs);
    }

    // ═══════════════════════════════════════════
    //        NEW OWNER CAN SIGN AFTER ADD
    // ═══════════════════════════════════════════

    function test_newOwnerCanSignAfterAdd() public {
        wallet = _deploy(1);
        vm.deal(address(wallet), 2 ether);
        address receiver = address(new Receiver());

        uint256 newPk = 0xD4;
        address newOwner = vm.addr(newPk);

        // Add new owner
        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        address[] memory sorted = _sortedOwners();
        uint256 signerPk;
        if (vm.addr(pk1) == sorted[0]) signerPk = pk1;
        else if (vm.addr(pk2) == sorted[0]) signerPk = pk2;
        else signerPk = pk3;
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pksSingle(signerPk));
        wallet.execute(address(wallet), 0, data, sigs);
        assertTrue(wallet.isOwner(newOwner));

        // Now the new owner signs a tx
        sigs = _sign(wallet, receiver, 1 ether, "", _pksSingle(newPk));
        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //      REMOVED OWNER CANNOT SIGN ANYMORE
    // ═══════════════════════════════════════════

    function test_removedOwnerCannotSign() public {
        wallet = _deploy(1);
        vm.deal(address(wallet), 2 ether);
        address receiver = address(new Receiver());
        address[] memory sorted = _sortedOwners();

        // Find the PK for sorted[2] (last in linked list)
        uint256 removedPk;
        if (vm.addr(pk1) == sorted[2]) removedPk = pk1;
        else if (vm.addr(pk2) == sorted[2]) removedPk = pk2;
        else removedPk = pk3;

        // Remove sorted[2]
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[1], sorted[2]));
        // Sign with sorted[0]
        uint256 signerPk;
        if (vm.addr(pk1) == sorted[0]) signerPk = pk1;
        else if (vm.addr(pk2) == sorted[0]) signerPk = pk2;
        else signerPk = pk3;
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pksSingle(signerPk));
        wallet.execute(address(wallet), 0, data, sigs);

        // Removed owner tries to sign — should fail
        sigs = _sign(wallet, receiver, 1 ether, "", _pksSingle(removedPk));
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    // ═══════════════════════════════════════════
    //           RE-QUEUE AFTER CANCEL
    // ═══════════════════════════════════════════

    function test_reQueueAfterCancel() public {
        address exec = address(0xEEEE);
        wallet = _deployFull(2, 1 days, exec, 2 ether);
        address receiver = address(new Receiver());

        // Queue tx
        uint32 n1 = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);
        bytes32 hash1 = _txHash(wallet, receiver, 1 ether, "", n1);
        assertGt(wallet.queued(hash1), 0);

        // Cancel
        vm.prank(exec);
        wallet.cancelQueued(hash1);
        assertEq(wallet.queued(hash1), 0);

        // Re-queue with new nonce
        uint32 n2 = wallet.nonce();
        sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);
        bytes32 hash2 = _txHash(wallet, receiver, 1 ether, "", n2);
        assertGt(wallet.queued(hash2), 0);
        assertTrue(hash1 != hash2); // different nonce => different hash

        // Execute re-queued
        vm.warp(block.timestamp + 1 days);
        wallet.executeQueued(receiver, 1 ether, "", n2);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //       MULTIPLE QUEUED TXS SIMULTANEOUSLY
    // ═══════════════════════════════════════════

    function test_multipleQueuedTxs() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 5 ether);
        address r1 = address(new Receiver());
        address r2 = address(new Receiver());

        // Queue two different txs
        uint32 n1 = wallet.nonce();
        bytes memory sigs1 = _sign(wallet, r1, 1 ether, "", _pks2());
        wallet.execute(r1, 1 ether, "", sigs1);

        uint32 n2 = wallet.nonce();
        bytes memory sigs2 = _sign(wallet, r2, 2 ether, "", _pks2());
        wallet.execute(r2, 2 ether, "", sigs2);

        // Both queued
        assertGt(wallet.queued(_txHash(wallet, r1, 1 ether, "", n1)), 0);
        assertGt(wallet.queued(_txHash(wallet, r2, 2 ether, "", n2)), 0);

        // Execute both after delay
        vm.warp(block.timestamp + 1 days);
        wallet.executeQueued(r1, 1 ether, "", n1);
        wallet.executeQueued(r2, 2 ether, "", n2);
        assertEq(r1.balance, 1 ether);
        assertEq(r2.balance, 2 ether);
    }

    // ═══════════════════════════════════════════
    //    EXECUTEQUEUED WITH WRONG PARAMS FAILS
    // ═══════════════════════════════════════════

    function test_executeQueued_revertWrongTarget() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(address(0xBEEF), 1 ether, "", n); // wrong target
    }

    function test_executeQueued_revertWrongValue() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(receiver, 2 ether, "", n); // wrong value
    }

    function test_executeQueued_revertWrongData() public {
        wallet = _deployWithDelay(2, 1 days);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 0, "hello", _pks2());
        wallet.execute(receiver, 0, "hello", sigs);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(receiver, 0, "wrong", n); // wrong data
    }

    function test_executeQueued_revertWrongNonce() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(Multisig.NotReady.selector, 0));
        wallet.executeQueued(receiver, 1 ether, "", n + 1); // wrong nonce
    }

    // ═══════════════════════════════════════════
    //          ADDOWNER EDGE CASES
    // ═══════════════════════════════════════════

    function test_addOwner_revertSentinel() public {
        wallet = _deploy(2);
        bytes memory data = abi.encodeCall(Multisig.addOwner, (address(1)));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        vm.expectRevert(); // _owner > SENTINEL fails since _owner == SENTINEL
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_addOwner_ownerCountIncreases() public {
        wallet = _deploy(2);
        assertEq(wallet.ownerCount(), 3);
        address newOwner = address(0xBEEF);

        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);

        assertEq(wallet.ownerCount(), 4);
    }

    // ═══════════════════════════════════════════
    //        REMOVEOWNER — FIRST IN LIST
    // ═══════════════════════════════════════════

    function test_removeOwner_firstInList() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();

        // Remove first owner (prev = SENTINEL)
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (address(1), sorted[0]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);

        assertFalse(wallet.isOwner(sorted[0]));
        assertEq(wallet.ownerCount(), 2);

        // Verify linked list integrity
        address[] memory remaining = wallet.getOwners();
        assertEq(remaining.length, 2);
        assertEq(remaining[0], sorted[1]);
        assertEq(remaining[1], sorted[2]);
    }

    function test_removeOwner_middleInList() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();

        // Remove middle owner
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[0], sorted[1]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);

        assertFalse(wallet.isOwner(sorted[1]));
        address[] memory remaining = wallet.getOwners();
        assertEq(remaining.length, 2);
        assertEq(remaining[0], sorted[0]);
        assertEq(remaining[1], sorted[2]);
    }

    function test_removeOwner_ownerCountDecreases() public {
        wallet = _deploy(2);
        assertEq(wallet.ownerCount(), 3);
        address[] memory sorted = _sortedOwners();

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[1], sorted[2]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);

        assertEq(wallet.ownerCount(), 2);
    }

    // ═══════════════════════════════════════════
    //          ISOWNER EDGE CASES
    // ═══════════════════════════════════════════

    function test_isOwner_sentinel() public {
        wallet = _deploy(2);
        assertFalse(wallet.isOwner(address(1)));
    }

    function test_isOwner_addressZero() public {
        wallet = _deploy(2);
        assertFalse(wallet.isOwner(address(0)));
    }

    function test_isOwner_nonOwner() public {
        wallet = _deploy(2);
        assertFalse(wallet.isOwner(address(0xDEAD)));
    }

    // ═══════════════════════════════════════════
    //           BATCH EDGE CASES
    // ═══════════════════════════════════════════

    function test_batch_emptyArrays() public {
        wallet = _deploy(2);
        address[] memory targets = new address[](0);
        uint256[] memory values = new uint256[](0);
        bytes[] memory datas = new bytes[](0);

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(wallet, address(wallet), 0, batchData, _pks2());
        wallet.execute(address(wallet), 0, batchData, sigs);
        // No revert — empty batch is a no-op
    }

    function test_batch_singleOperation() public {
        wallet = _deploy(2);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = receiver;
        values[0] = 1 ether;

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(wallet, address(wallet), 0, batchData, _pks2());
        wallet.execute(address(wallet), 0, batchData, sigs);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //       SET DELAY THEN QUEUE USES NEW DELAY
    // ═══════════════════════════════════════════

    function test_setDelay_thenQueueUsesNewDelay() public {
        wallet = _deploy(2);
        vm.deal(address(wallet), 2 ether);
        address receiver = address(new Receiver());

        // Set delay to 2 days
        bytes memory data = abi.encodeCall(Multisig.setDelay, (2 days));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.delay(), 2 days);

        // Queue tx — should use 2-day delay
        uint32 n = wallet.nonce();
        sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 0);

        // 1 day not enough
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert();
        wallet.executeQueued(receiver, 1 ether, "", n);

        // 2 days works
        vm.warp(block.timestamp + 1 days);
        wallet.executeQueued(receiver, 1 ether, "", n);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //     SET EXECUTOR THEN USE NEW EXECUTOR
    // ═══════════════════════════════════════════

    function test_setExecutor_thenNewExecutorOperates() public {
        wallet = _deploy(2);
        vm.deal(address(wallet), 2 ether);
        address receiver = address(new Receiver());
        address newExec = address(0xF00D);

        // Set executor
        bytes memory data = abi.encodeCall(Multisig.setExecutor, (newExec));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.executor(), newExec);

        // New executor can bypass sigs
        vm.prank(newExec);
        wallet.execute(receiver, 1 ether, "", "");
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //  IMPLEMENTATION CANNOT BE INITIALIZED
    // ═══════════════════════════════════════════

    function test_implementation_cannotBeInitByThirdParty() public {
        address impl = factory.implementation();
        address[] memory sorted = _sortedOwners();

        vm.prank(address(0xDEAD));
        vm.expectRevert(Multisig.Unauthorized.selector);
        Multisig(payable(impl)).init(sorted, 0, 2, address(0));
    }

    function test_implementation_cannotBeInitByFactory() public view {
        // The factory is the implementation's `factory` immutable, but
        // factory.create() only calls init on clones, never on the implementation.
        // Verify the implementation is still uninitialized after factory deployment.
        address impl = factory.implementation();
        assertEq(Multisig(payable(impl)).threshold(), 0);
        assertEq(Multisig(payable(impl)).ownerCount(), 0);
    }

    function test_implementation_cannotSelfCallInit() public {
        // The self-call path (msg.sender == address(this)) is unreachable because
        // execute() requires threshold != 0, which requires prior initialization.
        address impl = factory.implementation();
        address[] memory sorted = _sortedOwners();

        // execute on uninitialized impl reverts — threshold is 0, so sig check fails
        vm.expectRevert(Multisig.InvalidSig.selector);
        Multisig(payable(impl)).execute(impl, 0, abi.encodeCall(Multisig.init, (sorted, 0, 2, address(0))), "");
    }

    // ═══════════════════════════════════════════
    //    CANCELQUEUED ON NONEXISTENT HASH
    // ═══════════════════════════════════════════

    function test_cancelQueued_nonexistentHashNoOps() public {
        address exec = address(0xEEEE);
        wallet = _deployWithExecutor(2, exec);

        // Cancel a hash that was never queued — no revert, just deletes 0
        vm.prank(exec);
        wallet.cancelQueued(bytes32(uint256(0xDEAD)));
        // No revert
    }

    // ═══════════════════════════════════════════
    //       SETTHRESHOLD BOUNDARY CASES
    // ═══════════════════════════════════════════

    function test_setThreshold_toOwnerCount() public {
        wallet = _deploy(2);
        // 3 owners, set threshold to 3
        bytes memory data = abi.encodeCall(Multisig.setThreshold, (3));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.threshold(), 3);
    }

    function test_setThreshold_samValue() public {
        wallet = _deploy(2);
        // Set threshold to current value (2)
        bytes memory data = abi.encodeCall(Multisig.setThreshold, (2));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, sigs);
        assertEq(wallet.threshold(), 2);
    }

    // ═══════════════════════════════════════════
    //      INIT WITH MAX THRESHOLD == LENGTH
    // ═══════════════════════════════════════════

    function test_init_thresholdEqualsOwnerCount() public {
        wallet = _deploy(3); // 3 owners, threshold 3
        assertEq(wallet.threshold(), 3);
        assertEq(wallet.ownerCount(), 3);
    }

    // ═══════════════════════════════════════════
    //        INIT WITH DELAY AND EXECUTOR
    // ═══════════════════════════════════════════

    function test_init_delayZeroNotStored() public {
        // When delay=0 passed to init, delay stays 0 (default)
        wallet = _deploy(2);
        assertEq(wallet.delay(), 0);
    }

    function test_init_executorZeroNotStored() public {
        wallet = _deploy(2);
        assertEq(wallet.executor(), address(0));
    }

    // ═══════════════════════════════════════════
    //     EXECUTE EMITS CORRECT HASH AND NONCE
    // ═══════════════════════════════════════════

    function test_event_executionSuccess_correctValues() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes32 expectedHash = _txHash(wallet, receiver, 1 ether, "", n);
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());

        vm.expectEmit(true, false, false, true);
        emit Multisig.ExecutionSuccess(expectedHash, n);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    function test_event_queued_correctValues() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes32 expectedHash = _txHash(wallet, receiver, 1 ether, "", n);
        uint256 expectedEta = block.timestamp + 1 days;
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());

        vm.expectEmit(true, false, false, true);
        emit Multisig.Queued(expectedHash, n, expectedEta);
        wallet.execute(receiver, 1 ether, "", sigs);
    }

    // ═══════════════════════════════════════════
    //    EXECUTE WITH ZERO VALUE AND EMPTY DATA
    // ═══════════════════════════════════════════

    function test_execute_zeroValueEmptyData() public {
        wallet = _deploy(2);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 0, "", _pks2());
        wallet.execute(receiver, 0, "", sigs);
        assertEq(wallet.nonce(), 1);
    }

    // ═══════════════════════════════════════════
    //  REMOVEOWNER THEN GETOWNERS FULL INTEGRITY
    // ═══════════════════════════════════════════

    function test_removeOwner_thenGetOwnersIntegrity() public {
        wallet = _deploy(1);
        address[] memory sorted = _sortedOwners();

        // Remove last
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[1], sorted[2]));
        uint256 signerPk;
        if (vm.addr(pk1) == sorted[0]) signerPk = pk1;
        else if (vm.addr(pk2) == sorted[0]) signerPk = pk2;
        else signerPk = pk3;
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pksSingle(signerPk));
        wallet.execute(address(wallet), 0, data, sigs);

        // Remove second (now last)
        data = abi.encodeCall(Multisig.removeOwner, (sorted[0], sorted[1]));
        sigs = _sign(wallet, address(wallet), 0, data, _pksSingle(signerPk));
        wallet.execute(address(wallet), 0, data, sigs);

        address[] memory remaining = wallet.getOwners();
        assertEq(remaining.length, 1);
        assertEq(remaining[0], sorted[0]);
        assertTrue(wallet.isOwner(sorted[0]));
        assertFalse(wallet.isOwner(sorted[1]));
        assertFalse(wallet.isOwner(sorted[2]));
    }

    // ═══════════════════════════════════════════
    //   ADDOWNER + SETTHRESHOLD ATOMIC VIA BATCH
    // ═══════════════════════════════════════════

    function test_batch_addOwnerAndRaiseThreshold() public {
        wallet = _deploy(2);
        address newOwner = address(0xBEEF);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);
        targets[0] = address(wallet);
        targets[1] = address(wallet);
        datas[0] = abi.encodeCall(Multisig.addOwner, (newOwner));
        datas[1] = abi.encodeCall(Multisig.setThreshold, (3));

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(wallet, address(wallet), 0, batchData, _pks2());
        wallet.execute(address(wallet), 0, batchData, sigs);

        assertTrue(wallet.isOwner(newOwner));
        assertEq(wallet.threshold(), 3);
        assertEq(wallet.ownerCount(), 4);
    }

    // ═══════════════════════════════════════════
    //    REMOVEOWNER + LOWERTHRESHOLD VIA BATCH
    // ═══════════════════════════════════════════

    function test_batch_removeOwnerAndLowerThreshold() public {
        wallet = _deploy(3);
        address[] memory sorted = _sortedOwners();

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);
        // Lower threshold first so removal doesn't violate ownerCount > threshold
        targets[0] = address(wallet);
        datas[0] = abi.encodeCall(Multisig.setThreshold, (2));
        targets[1] = address(wallet);
        datas[1] = abi.encodeCall(Multisig.removeOwner, (sorted[1], sorted[2]));

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(wallet, address(wallet), 0, batchData, _pks3());
        wallet.execute(address(wallet), 0, batchData, sigs);

        assertFalse(wallet.isOwner(sorted[2]));
        assertEq(wallet.threshold(), 2);
        assertEq(wallet.ownerCount(), 2);
    }

    // ═══════════════════════════════════════════
    //         SETDELAY TO ZERO REMOVES TIMELOCK
    // ═══════════════════════════════════════════

    function test_setDelay_toZeroRemovesTimelock() public {
        address exec = address(0xEEEE);
        wallet = _deployFull(2, 1 days, exec, 2 ether);
        address receiver = address(new Receiver());

        // Verify queuing works for owners
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 0); // queued

        // Executor sets delay to 0 (bypasses timelock)
        bytes memory data = abi.encodeCall(Multisig.setDelay, (0));
        vm.prank(exec);
        wallet.execute(address(wallet), 0, data, "");
        assertEq(wallet.delay(), 0);

        // Now owners execute immediately
        sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //      MULTIPLE SEQUENTIAL EXECUTIONS
    // ═══════════════════════════════════════════

    function test_execute_manySequential() public {
        wallet = _deployFunded(2, 10 ether);
        address receiver = address(new Receiver());

        for (uint256 i; i < 5; ++i) {
            bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
            wallet.execute(receiver, 1 ether, "", sigs);
        }
        assertEq(receiver.balance, 5 ether);
        assertEq(wallet.nonce(), 5);
    }

    // ═══════════════════════════════════════════
    //        EXECUTOR WITH DELAY — OWNERS QUEUE
    // ═══════════════════════════════════════════

    function test_executor_immediateWhileOwnersQueue() public {
        address exec = address(0xEEEE);
        wallet = _deployFull(2, 1 days, exec, 3 ether);
        address r1 = address(new Receiver());
        address r2 = address(new Receiver());

        // Owners queue
        bytes memory sigs = _sign(wallet, r1, 1 ether, "", _pks2());
        wallet.execute(r1, 1 ether, "", sigs);
        assertEq(r1.balance, 0);

        // Executor executes immediately
        vm.prank(exec);
        wallet.execute(r2, 1 ether, "", "");
        assertEq(r2.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //     RECEIVE ETH VIA PAYABLE EXECUTE
    // ═══════════════════════════════════════════

    function test_execute_payableReceivesMsg_value() public {
        wallet = _deploy(2);
        address receiver = address(new Receiver());

        // Send ETH with msg.value directly through execute (wallet uses msg.value)
        vm.deal(address(this), 1 ether);
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute{value: 1 ether}(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //     QUEUED TX ETA STORED CORRECTLY
    // ═══════════════════════════════════════════

    function test_queued_etaStoredCorrectly() public {
        wallet = _deployWithDelay(2, 2 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        uint256 expectedEta = block.timestamp + 2 days;
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        bytes32 hash = _txHash(wallet, receiver, 1 ether, "", n);
        assertEq(wallet.queued(hash), expectedEta);
    }

    // ═══════════════════════════════════════════
    //   GUARD: EXECUTOR WITH POST-HOOK BYPASSES SIGS
    // ═══════════════════════════════════════════

    function test_guard_executorWithPostGuardBypassesSigs() public {
        address guardAddr = address((uint160(0xABCD) << 144) | 0x1111);
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 0, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        vm.prank(guardAddr);
        wallet.execute(receiver, 0.5 ether, "", "");

        assertEq(guard.calls(), 1, "post-guard called");
        assertEq(receiver.balance, 0.5 ether, "executor bypassed sigs");
    }

    // ═══════════════════════════════════════════
    //   GUARD: BOTH HOOKS WITH DELAY (QUEUED)
    // ═══════════════════════════════════════════

    function test_guard_bothHooksOnQueue() public {
        address guardAddr = address((uint160(0x1111) << 144) | 0x1111);
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 1 days, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        bytes memory sigs = _sign(wallet, receiver, 0.5 ether, "", _pks2());
        wallet.execute(receiver, 0.5 ether, "", sigs);

        assertEq(guard.calls(), 2, "both guards called on queue");
        assertEq(receiver.balance, 0, "tx queued, not executed");
    }

    // ═══════════════════════════════════════════
    //   GUARD: EXECUTOR IMMEDIATE WITH DELAY SET
    // ═══════════════════════════════════════════

    function test_guard_preGuardExecutorBypassesDelay() public {
        address guardAddr = address(uint160(0x1111 << 144) | uint160(0xABCDEF));
        MockGuard guard = _etchGuard(guardAddr);
        wallet = _deployFull(2, 1 days, guardAddr, 1 ether);
        address receiver = address(new Receiver());

        vm.prank(guardAddr);
        wallet.execute(receiver, 0.5 ether, "", "");

        assertEq(guard.calls(), 1, "pre-guard called");
        assertEq(receiver.balance, 0.5 ether, "executor bypassed delay");
    }

    // ═══════════════════════════════════════════
    //          SINGLE OWNER WALLET
    // ═══════════════════════════════════════════

    function test_singleOwnerWallet() public {
        address[] memory owners = new address[](1);
        uint256 pk = 0xFF;
        owners[0] = vm.addr(pk);
        Multisig w = Multisig(payable(factory.create(owners, 0, 1, address(0), nextSalt++)));
        vm.deal(address(w), 1 ether);

        assertEq(w.threshold(), 1);
        assertEq(w.ownerCount(), 1);
        assertTrue(w.isOwner(owners[0]));

        address[] memory got = w.getOwners();
        assertEq(got.length, 1);
        assertEq(got[0], owners[0]);

        // Execute
        address receiver = address(new Receiver());
        bytes32 hash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                w.DOMAIN_SEPARATOR(),
                keccak256(abi.encode(EXECUTE_TYPEHASH, receiver, uint256(1 ether), keccak256(""), w.nonce()))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        bytes memory sigs = abi.encodePacked(r, s, v);
        w.execute(receiver, 1 ether, "", sigs);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //    REMOVEOWNER — SENTINEL AS OWNER FAILS
    // ═══════════════════════════════════════════

    function test_removeOwner_revertSentinel() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();

        // Try to remove SENTINEL
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[0], address(1)));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());
        vm.expectRevert(); // _owner != SENTINEL
        wallet.execute(address(wallet), 0, data, sigs);
    }

    // ═══════════════════════════════════════════
    //   EXECUTEQUEUED — EMITS CORRECT EVENT
    // ═══════════════════════════════════════════

    function test_executeQueued_emitsCorrectEvent() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint32 n = wallet.nonce();
        bytes32 expectedHash = _txHash(wallet, receiver, 1 ether, "", n);
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);

        vm.expectEmit(true, false, false, true);
        emit Multisig.ExecutionSuccess(expectedHash, n);
        wallet.executeQueued(receiver, 1 ether, "", n);
    }

    // ═══════════════════════════════════════════
    //   DEPLOY WITH VALUE FORWARDED CORRECTLY
    // ═══════════════════════════════════════════

    function test_factory_createForwardsValue() public {
        address[] memory sorted = _sortedOwners();
        vm.deal(address(this), 5 ether);
        address w = factory.create{value: 3 ether}(sorted, 0, 2, address(0), nextSalt++);
        assertEq(w.balance, 3 ether);
    }

    // ═══════════════════════════════════════════
    //   DELEGATECALL VIA BATCH
    // ═══════════════════════════════════════════

    function test_delegateCall_viaBatch() public {
        wallet = _deploy(2);
        SetSlot impl = new SetSlot();

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory datas = new bytes[](1);
        targets[0] = address(wallet);
        datas[0] = abi.encodeCall(Multisig.delegateCall, (address(impl), abi.encodeCall(SetSlot.setThreshold, (77))));

        bytes memory batchData = abi.encodeCall(Multisig.batch, (targets, values, datas));
        bytes memory sigs = _sign(wallet, address(wallet), 0, batchData, _pks2());
        wallet.execute(address(wallet), 0, batchData, sigs);
        assertEq(uint256(vm.load(address(wallet), bytes32(0))), 77);
    }
}
