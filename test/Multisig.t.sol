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
    bytes32 constant EXECUTE_TYPEHASH = keccak256("Execute(address target,uint256 value,bytes data,uint48 nonce)");
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

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[2]));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, sigs);
        assertFalse(wallet.isOwner(sorted[2]));
    }

    function test_removeOwner_revertNotSelf() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();
        vm.expectRevert(Multisig.Unauthorized.selector);
        wallet.removeOwner(sorted[0]);
    }

    function test_removeOwner_revertNotOwner() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (address(0xDEAD)));
        bytes memory sigs = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(); // require(isOwner[_owner])
        wallet.execute(address(wallet), 0, data, sigs);
    }

    function test_removeOwner_revertBelowThreshold() public {
        wallet = _deploy(3);
        address[] memory sorted = _sortedOwners();

        // removing any owner would leave 2 owners < threshold 3
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[0]));
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

        // remove owner
        data = abi.encodeCall(Multisig.removeOwner, (newOwner));
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
        assertEq(keccak256("Execute(address target,uint256 value,bytes data,uint48 nonce)"), EXECUTE_TYPEHASH);
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

        // remove
        data = abi.encodeCall(Multisig.removeOwner, (newOwner));
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

        uint48 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        assertEq(receiver.balance, 0);
        assertEq(wallet.nonce(), n + 1);
    }

    function test_timelock_executeQueuedAfterDelay() public {
        wallet = _deployWithDelay(2, 1 days);
        vm.deal(address(wallet), 1 ether);
        address receiver = address(new Receiver());

        uint48 n = wallet.nonce();
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

        uint48 n = wallet.nonce();
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

        uint48 n = wallet.nonce();
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

        uint48 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, rev, 1 ether, "", _pks2());
        wallet.execute(rev, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(bytes("nope"));
        wallet.executeQueued(rev, 1 ether, "", n);
    }

    function test_timelock_executeQueuedWithData() public {
        wallet = _deployWithDelay(2, 1 days);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (1));
        uint48 n = wallet.nonce();
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

        uint48 n = wallet.nonce();
        bytes memory sigs = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", sigs);

        vm.warp(block.timestamp + 1 days);
        vm.prank(address(0xCAFE));
        wallet.executeQueued(receiver, 1 ether, "", n);
        assertEq(receiver.balance, 1 ether);
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

        uint48 n = wallet.nonce();
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

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[2]));
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

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (toRemove));
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
}
