// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

contract Multisig {
    uint128 public nonce;
    uint128 public threshold;
    bytes32 constant EXECUTE_TYPEHASH = keccak256("Execute(address to,uint256 value,bytes data,uint128 nonce)");

    address[] public owners;
    mapping(address => bool) public isOwner;

    error InvalidSig();
    error InvalidInit();
    error InvalidCall();
    error Unauthorized();
    error InvalidConfig();

    modifier onlySelf() {
        require(msg.sender == address(this), Unauthorized());
        _;
    }

    function init(address[] calldata _owners, uint128 _threshold) public payable {
        uint256 len = _owners.length;
        require(threshold == 0, InvalidInit());
        require(_threshold != 0, InvalidInit());
        require(_threshold <= len, InvalidInit());
        threshold = _threshold;
        address prev;
        address owner;
        for (uint256 i; i != len; ++i) {
            owner = _owners[i];
            require(owner > prev, InvalidInit());
            isOwner[owner] = true;
            owners.push(owner);
            prev = owner;
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
            address signer;
            uint256 _threshold = threshold;
            for (uint256 i; i != _threshold; ++i) {
                signer = ecrecover(hash, v[i], r[i], s[i]);
                require(isOwner[signer], InvalidSig());
                require(signer > prev, InvalidSig());
                prev = signer;
            }

            (bool ok,) = to.call{value: value}(data);
            require(ok, InvalidCall());
        }
    }

    function addOwner(address _owner) public payable onlySelf {
        require(!isOwner[_owner], InvalidConfig());
        require(_owner != address(0), InvalidConfig());
        isOwner[_owner] = true;
        owners.push(_owner);
    }

    function removeOwner(address _owner) public payable onlySelf {
        unchecked {
            uint256 len = owners.length;
            require(isOwner[_owner], InvalidConfig());
            require(len - 1 >= threshold, InvalidConfig());
            isOwner[_owner] = false;
            for (uint256 i; i != len; ++i) {
                if (owners[i] == _owner) {
                    owners[i] = owners[len - 1];
                    owners.pop();
                    break;
                }
            }
        }
    }

    function setThreshold(uint128 _threshold) public payable onlySelf {
        require(_threshold != 0, InvalidConfig());
        require(_threshold <= owners.length, InvalidConfig());
        threshold = _threshold;
    }

    receive() external payable {}

    /// @dev Handles all ERC721 and ERC1155 token safety callbacks.
    /// Adapted from Solady (https://github.com/Vectorized/solady/blob/main/src/accounts/Receiver.sol)
    fallback() external payable {
        assembly ("memory-safe") {
            let s := shr(224, calldataload(0))
            if or(eq(s, 0x150b7a02), or(eq(s, 0xf23a6e61), eq(s, 0xbc197c81))) {
                mstore(0x20, s)
                return(0x3c, 0x20)
            }
        }
    }
}

contract MultisigFactory {
    event Created(address indexed wallet);

    address public immutable implementation;

    error DeploymentFailed();
    error SaltDoesNotStartWith();

    constructor() payable {
        implementation = address(new Multisig{salt: bytes32(0)}());
        address[] memory lock = new address[](1);
        lock[0] = address(1);
        Multisig(payable(implementation)).init(lock, 1);
    }

    /// @dev Create deterministic multisig wallet with PUSH0 and CREATE2.
    /// Adapted from Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibClone.sol).
    /// The salt must start with the zero address or the caller for front-running protection.
    function create(address[] calldata _owners, uint128 _threshold, uint256 salt)
        public
        payable
        returns (address wallet)
    {
        address impl = implementation;
        assembly ("memory-safe") {
            if iszero(or(iszero(shr(96, salt)), eq(shr(96, salt), caller()))) {
                mstore(0x00, 0x0c4549ef) // SaltDoesNotStartWith()
                revert(0x1c, 0x04)
            }
            mstore(0x24, 0x5af43d5f5f3e6029573d5ffd5b3d5ff3)
            mstore(0x14, impl)
            mstore(0x00, 0x602d5f8160095f39f35f5f365f5f37365f73)
            wallet := create2(0, 0x0e, 0x36, salt)
            if iszero(wallet) {
                mstore(0x00, 0x30116425) // DeploymentFailed()
                revert(0x1c, 0x04)
            }
            mstore(0x24, 0)
        }
        Multisig(payable(wallet)).init{value: msg.value}(_owners, _threshold);
        emit Created(wallet);
    }
}
