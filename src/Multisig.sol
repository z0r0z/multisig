// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

contract Multisig {
    uint128 public nonce;
    uint128 public threshold;
    bytes32 constant EXECUTE_TYPEHASH = keccak256("Execute(address to,uint256 value,bytes data,uint128 nonce)");

    address[] public owners;
    mapping(address => bool) public isOwner;

    modifier onlySelf() {
        require(msg.sender == address(this), Unauthorized());
        _;
    }

    error InvalidSig();
    error InvalidInit();
    error Unauthorized();

    function init(address[] calldata _owners, uint128 _threshold) public payable {
        require(threshold == 0, InvalidInit());
        require(_threshold > 0 && _threshold <= _owners.length, InvalidInit());
        threshold = _threshold;
        address prev;
        for (uint256 i; i != _owners.length; ++i) {
            require(_owners[i] > prev, InvalidInit());
            isOwner[_owners[i]] = true;
            owners.push(_owners[i]);
            prev = _owners[i];
        }
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Multisig"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint8[] calldata v,
        bytes32[] calldata r,
        bytes32[] calldata s
    ) public payable {
        unchecked {
            bytes32 hash = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(EXECUTE_TYPEHASH, to, value, keccak256(data), nonce++))
                )
            );

            address prev;
            uint256 _threshold = threshold;
            for (uint256 i; i != _threshold; ++i) {
                address signer = ecrecover(hash, v[i], r[i], s[i]);
                require(isOwner[signer] && signer > prev, InvalidSig());
                prev = signer;
            }

            (bool ok,) = to.call{value: value}(data);
            require(ok);
        }
    }

    function addOwner(address _owner) public payable onlySelf {
        require(!isOwner[_owner], Unauthorized());
        require(_owner != address(0), Unauthorized());
        isOwner[_owner] = true;
        owners.push(_owner);
    }

    function removeOwner(address _owner) public payable onlySelf {
        require(isOwner[_owner], Unauthorized());
        isOwner[_owner] = false;
        uint256 len = owners.length;
        for (uint256 i; i != len; ++i) {
            unchecked {
                if (owners[i] == _owner) {
                    owners[i] = owners[len - 1];
                    owners.pop();
                    break;
                }
            }
        }
        require(owners.length >= threshold);
    }

    function setThreshold(uint128 _threshold) public payable onlySelf {
        require(_threshold > 0 && _threshold <= owners.length, Unauthorized());
        threshold = _threshold;
    }

    receive() external payable {}

    fallback() external payable {
        assembly ("memory-safe") {
            let s := shr(224, calldataload(0))
            // 0x150b7a02: `onERC721Received(address,address,uint256,bytes)`.
            // 0xf23a6e61: `onERC1155Received(address,address,uint256,uint256,bytes)`.
            // 0xbc197c81: `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)`.
            if or(eq(s, 0x150b7a02), or(eq(s, 0xf23a6e61), eq(s, 0xbc197c81))) {
                mstore(0x20, s) // Load into memory slot.
                return(0x3c, 0x20) // Return `msg.sig`.
            }
        }
    }
}

contract MultisigFactory {
    address public immutable implementation;

    event Created(address indexed wallet);

    error DeploymentFailed();

    constructor() payable {
        implementation = address(new Multisig{salt: bytes32(0)}());
        address[] memory lock = new address[](1);
        lock[0] = address(1);
        Multisig(payable(implementation)).init(lock, 1);
    }

    function create(address[] calldata _owners, uint128 _threshold) public payable returns (address wallet) {
        wallet = _clonePUSH0(implementation);
        Multisig(payable(wallet)).init{value: msg.value}(_owners, _threshold);
        emit Created(wallet);
    }

    /// @dev Deploys a PUSH0 clone of `impl`.
    /// Adapted from Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibClone.sol)
    function _clonePUSH0(address impl) internal returns (address instance) {
        assembly ("memory-safe") {
            mstore(0x24, 0x5af43d5f5f3e6029573d5ffd5b3d5ff3) // 16
            mstore(0x14, impl) // 20
            mstore(0x00, 0x602d5f8160095f39f35f5f365f5f37365f73) // 9 + 9
            instance := create(0, 0x0e, 0x36)
            if iszero(instance) {
                mstore(0x00, 0x30116425) // `DeploymentFailed()`
                revert(0x1c, 0x04)
            }
            mstore(0x24, 0) // Restore the overwritten part of the free memory pointer.
        }
    }
}
