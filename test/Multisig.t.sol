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
    bytes32 constant EXECUTE_TYPEHASH = keccak256("Execute(address to,uint256 value,bytes data,uint256 nonce)");

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

    function _deploy(uint256 threshold) internal returns (Multisig) {
        address[] memory sorted = _sortedOwners();
        return Multisig(payable(factory.create(sorted, threshold)));
    }

    function _deployFunded(uint256 threshold, uint256 amount) internal returns (Multisig) {
        address[] memory sorted = _sortedOwners();
        vm.deal(address(this), amount);
        return Multisig(payable(factory.create{value: amount}(sorted, threshold)));
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
        returns (uint8[] memory v, bytes32[] memory r, bytes32[] memory s)
    {
        bytes32 hash = _digest(w, to, value, data);
        v = new uint8[](pks.length);
        r = new bytes32[](pks.length);
        s = new bytes32[](pks.length);
        for (uint256 i; i < pks.length; ++i) {
            (v[i], r[i], s[i]) = vm.sign(pks[i], hash);
        }
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

    function test_factory_implementationLocked() public view {
        address impl = factory.implementation();
        Multisig m = Multisig(payable(impl));
        assertEq(m.threshold(), 1);
        assertTrue(m.isOwner(address(1)));
    }

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
        address w1 = factory.create(sorted, 2);
        address w2 = factory.create(sorted, 2);
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
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", _pks2());
        wallet.execute(receiver, 1 ether, "", v, r, s);
        assertEq(receiver.balance, 1 ether);
    }

    function test_factory_emitsCreated() public {
        address[] memory sorted = _sortedOwners();
        vm.expectEmit(false, false, false, false);
        emit MultisigFactory.Created(address(0)); // we don't know the address yet
        factory.create(sorted, 2);
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
        vm.expectRevert(Multisig.InvalidInit.selector);
        wallet.init(sorted, 2);
    }

    function test_init_revertThresholdZero() public {
        address[] memory sorted = _sortedOwners();
        vm.expectRevert(Multisig.InvalidInit.selector);
        factory.create(sorted, 0);
    }

    function test_init_revertThresholdTooHigh() public {
        address[] memory sorted = _sortedOwners();
        vm.expectRevert(Multisig.InvalidInit.selector);
        factory.create(sorted, 4);
    }

    function test_init_revertUnsortedOwners() public {
        address[] memory sorted = _sortedOwners();
        // swap first two to break sort
        (sorted[0], sorted[1]) = (sorted[1], sorted[0]);
        vm.expectRevert(Multisig.InvalidInit.selector);
        factory.create(sorted, 2);
    }

    function test_init_revertDuplicateOwners() public {
        address[] memory dup = new address[](2);
        dup[0] = owner1;
        dup[1] = owner1;
        vm.expectRevert(Multisig.InvalidInit.selector);
        factory.create(dup, 1);
    }

    function test_init_revertAddressZeroOwner() public {
        address[] memory arr = new address[](1);
        arr[0] = address(0);
        vm.expectRevert(Multisig.InvalidInit.selector);
        factory.create(arr, 1);
    }

    // ═══════════════════════════════════════════
    //              EXECUTE TESTS
    // ═══════════════════════════════════════════

    function test_execute_sendETH() public {
        wallet = _deployFunded(2, 5 ether);
        address receiver = address(new Receiver());

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", _pks2());

        wallet.execute(receiver, 1 ether, "", v, r, s);
        assertEq(receiver.balance, 1 ether);
        assertEq(address(wallet).balance, 4 ether);
        assertEq(wallet.nonce(), 1);
    }

    function test_execute_callWithData() public {
        wallet = _deployFunded(2, 0);
        // call setThreshold on self
        bytes memory data = abi.encodeCall(Multisig.setThreshold, (1));

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, v, r, s);
        assertEq(wallet.threshold(), 1);
    }

    function test_execute_allSigners() public {
        wallet = _deployFunded(3, 1 ether);
        address receiver = address(new Receiver());

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", _pks3());

        wallet.execute(receiver, 1 ether, "", v, r, s);
        assertEq(receiver.balance, 1 ether);
    }

    function test_execute_incrementsNonce() public {
        wallet = _deployFunded(2, 10 ether);
        address receiver = address(new Receiver());

        for (uint256 i; i < 3; ++i) {
            (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", _pks2());
            wallet.execute(receiver, 1 ether, "", v, r, s);
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

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", pks);

        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", v, r, s);
    }

    function test_execute_revertDuplicateSigner() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        uint256[] memory pks = new uint256[](2);
        pks[0] = pk1;
        pks[1] = pk1; // same signer twice

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", pks);

        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", v, r, s);
    }

    function test_execute_revertWrongOrder() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        // sign in descending order (wrong)
        uint256[] memory pks = _pks2();
        // reverse
        (pks[0], pks[1]) = (pks[1], pks[0]);

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", pks);

        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", v, r, s);
    }

    function test_execute_revertReplayNonce() public {
        wallet = _deployFunded(2, 10 ether);
        address receiver = address(new Receiver());

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", _pks2());

        wallet.execute(receiver, 1 ether, "", v, r, s);

        // same sigs, but nonce has advanced
        vm.expectRevert(Multisig.InvalidSig.selector);
        wallet.execute(receiver, 1 ether, "", v, r, s);
    }

    function test_execute_revertCallFails() public {
        wallet = _deployFunded(2, 1 ether);
        address rev = address(new Reverter());

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, rev, 1 ether, "", _pks2());

        vm.expectRevert();
        wallet.execute(rev, 1 ether, "", v, r, s);
    }

    function test_execute_revertInsufficientSigs() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());

        // only 1 sig for threshold=2
        uint256[] memory pks = new uint256[](1);
        pks[0] = pk1;

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, receiver, 1 ether, "", pks);

        vm.expectRevert(); // out of bounds
        wallet.execute(receiver, 1 ether, "", v, r, s);
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

        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) =
            _sign(wallet, receiver, 1 ether, "", _pksSingle(pk));

        wallet.execute(receiver, 1 ether, "", v, r, s);
        assertEq(receiver.balance, 1 ether);
    }

    // ═══════════════════════════════════════════
    //           OWNER MANAGEMENT TESTS
    // ═══════════════════════════════════════════

    function test_addOwner() public {
        wallet = _deploy(2);
        address newOwner = address(0xBEEF);

        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, v, r, s);
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
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(); // require(!isOwner[_owner])
        wallet.execute(address(wallet), 0, data, v, r, s);
    }

    function test_addOwner_revertAddressZero() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.addOwner, (address(0)));
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(); // require(_owner != address(0))
        wallet.execute(address(wallet), 0, data, v, r, s);
    }

    function test_removeOwner() public {
        wallet = _deploy(2);
        address[] memory sorted = _sortedOwners();

        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[2]));
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, v, r, s);
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
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert(); // require(isOwner[_owner])
        wallet.execute(address(wallet), 0, data, v, r, s);
    }

    function test_removeOwner_revertBelowThreshold() public {
        wallet = _deploy(3);
        address[] memory sorted = _sortedOwners();

        // removing any owner would leave 2 owners < threshold 3
        bytes memory data = abi.encodeCall(Multisig.removeOwner, (sorted[0]));
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks3());

        vm.expectRevert(); // require(owners.length >= threshold)
        wallet.execute(address(wallet), 0, data, v, r, s);
    }

    function test_setThreshold() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (3));
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        wallet.execute(address(wallet), 0, data, v, r, s);
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
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert();
        wallet.execute(address(wallet), 0, data, v, r, s);
    }

    function test_setThreshold_revertTooHigh() public {
        wallet = _deploy(2);

        bytes memory data = abi.encodeCall(Multisig.setThreshold, (4));
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());

        vm.expectRevert();
        wallet.execute(address(wallet), 0, data, v, r, s);
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
        bytes4 ret = wallet.onERC721Received(address(0), address(0), 0, "");
        assertEq(ret, wallet.onERC721Received.selector);
    }

    function test_onERC1155Received() public {
        wallet = _deploy(2);
        bytes4 ret = wallet.onERC1155Received(address(0), address(0), 0, 0, "");
        assertEq(ret, wallet.onERC1155Received.selector);
    }

    // ═══════════════════════════════════════════
    //              EIP-712 TESTS
    // ═══════════════════════════════════════════

    function test_domainSeparatorMatchesExpected() public {
        wallet = _deploy(2);
        assertEq(wallet.DOMAIN_SEPARATOR(), _domainSeparator(address(wallet)));
    }

    // ═══════════════════════════════════════════
    //           COMBINED FLOW TESTS
    // ═══════════════════════════════════════════

    function test_addThenRemoveOwner() public {
        wallet = _deploy(2);
        address newOwner = address(0xBEEF);

        // add
        bytes memory data = abi.encodeCall(Multisig.addOwner, (newOwner));
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, v, r, s);
        assertTrue(wallet.isOwner(newOwner));

        // remove
        data = abi.encodeCall(Multisig.removeOwner, (newOwner));
        (v, r, s) = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, v, r, s);
        assertFalse(wallet.isOwner(newOwner));
    }

    function test_lowerThresholdThenExecuteWith1() public {
        wallet = _deployFunded(2, 1 ether);
        address receiver = address(new Receiver());
        address[] memory sorted = _sortedOwners();

        // lower threshold to 1
        bytes memory data = abi.encodeCall(Multisig.setThreshold, (1));
        (uint8[] memory v, bytes32[] memory r, bytes32[] memory s) = _sign(wallet, address(wallet), 0, data, _pks2());
        wallet.execute(address(wallet), 0, data, v, r, s);
        assertEq(wallet.threshold(), 1);

        // now execute with single sig
        uint256 pk;
        if (vm.addr(pk1) == sorted[0]) pk = pk1;
        else if (vm.addr(pk2) == sorted[0]) pk = pk2;
        else pk = pk3;

        (v, r, s) = _sign(wallet, receiver, 1 ether, "", _pksSingle(pk));
        wallet.execute(receiver, 1 ether, "", v, r, s);
        assertEq(receiver.balance, 1 ether);
    }
}
