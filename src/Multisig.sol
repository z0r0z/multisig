// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

contract Multisig {
    event AddedOwner(address indexed owner);
    event RemovedOwner(address indexed owner);
    event ChangedThreshold(uint256 threshold);
    event ExecutionSuccess(bytes32 indexed txHash, uint256 nonce);

    error InvalidSig();
    error Unauthorized();
    error InvalidConfig();

    uint128 public nonce;
    uint128 public threshold;

    address[] owners;
    mapping(address => bool) public isOwner;

    modifier onlySelf() {
        require(msg.sender == address(this), Unauthorized());
        _;
    }

    function init(address[] calldata _owners, uint128 _threshold) public payable {
        uint256 len = _owners.length;
        require(threshold == 0 && _threshold != 0 && _threshold <= len, InvalidConfig());
        threshold = _threshold;
        address prev;
        address owner;
        for (uint256 i; i != len; ++i) {
            owner = _owners[i];
            require(owner > prev, InvalidConfig());
            isOwner[owner] = true;
            owners.push(owner);
            prev = owner;
        }
    }

    function getOwners() public view returns (address[] memory) {
        return owners;
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

    function isValidSignature(bytes32 hash, bytes calldata sigs) public view returns (bytes4) {
        unchecked {
            bytes32 safe = keccak256(
                abi.encodePacked(
                    "\x19\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(keccak256("SafeMessage(bytes32 hash)"), hash))
                )
            );
            uint256 _threshold = threshold;
            require(sigs.length == _threshold * 65, InvalidSig());
            uint256 o;
            address prev;
            address signer;
            for (uint256 i; i != _threshold; ++i) {
                o = i * 65;
                signer = ecrecover(safe, uint8(sigs[o + 64]), bytes32(sigs[o:o + 32]), bytes32(sigs[o + 32:o + 64]));
                require(signer != address(0) && isOwner[signer] && signer > prev, InvalidSig());
                prev = signer;
            }
        }
        return this.isValidSignature.selector;
    }

    function execute(address to, uint256 value, bytes calldata data, bytes calldata sigs) public payable {
        unchecked {
            (uint128 _nonce, uint128 _threshold) = (nonce++, threshold);
            bytes32 hash = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            keccak256("Execute(address to,uint256 value,bytes data,uint128 nonce)"),
                            to,
                            value,
                            keccak256(data),
                            _nonce
                        )
                    )
                )
            );

            uint256 o;
            address prev;
            address signer;
            require(sigs.length == _threshold * 65, InvalidSig());
            for (uint256 i; i != _threshold; ++i) {
                o = i * 65;
                signer = ecrecover(hash, uint8(sigs[o + 64]), bytes32(sigs[o:o + 32]), bytes32(sigs[o + 32:o + 64]));
                require(signer != address(0) && isOwner[signer] && signer > prev, InvalidSig());
                prev = signer;
            }

            (bool ok, bytes memory ret) = to.call{value: value}(data);
            if (!ok) assembly { revert(add(ret, 0x20), mload(ret)) }
            emit ExecutionSuccess(hash, _nonce);
        }
    }

    function addOwner(address _owner) public payable onlySelf {
        require(_owner != address(0) && !isOwner[_owner], InvalidConfig());
        isOwner[_owner] = true;
        owners.push(_owner);
        emit AddedOwner(_owner);
    }

    function removeOwner(address _owner) public payable onlySelf {
        unchecked {
            uint256 len = owners.length;
            require(len > threshold && isOwner[_owner], InvalidConfig());
            isOwner[_owner] = false;
            for (uint256 i; i != len; ++i) {
                if (owners[i] == _owner) {
                    owners[i] = owners[len - 1];
                    owners.pop();
                    break;
                }
            }
            emit RemovedOwner(_owner);
        }
    }

    function setThreshold(uint128 _threshold) public payable onlySelf {
        require(_threshold != 0 && _threshold <= owners.length, InvalidConfig());
        emit ChangedThreshold(threshold = _threshold);
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

    error DeploymentFailed();
    error SaltDoesNotStartWith();

    address public immutable implementation;

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
        require(salt >> 96 == 0 || salt >> 96 == uint160(msg.sender), SaltDoesNotStartWith());
        assembly ("memory-safe") {
            mstore(0x24, 0x5af43d5f5f3e6029573d5ffd5b3d5ff3)
            mstore(0x14, impl)
            mstore(0x00, 0x602d5f8160095f39f35f5f365f5f37365f73)
            wallet := create2(callvalue(), 0x0e, 0x36, salt)
            if iszero(wallet) {
                mstore(0x00, 0x30116425) // DeploymentFailed()
                revert(0x1c, 0x04)
            }
            mstore(0x24, 0)
        }
        Multisig(payable(wallet)).init(_owners, _threshold);
        emit Created(wallet);
    }
}
