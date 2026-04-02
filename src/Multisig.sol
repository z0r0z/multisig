// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

contract Multisig {
    event ChangedDelay(uint256 delay);
    event AddedOwner(address indexed owner);
    event RemovedOwner(address indexed owner);
    event ChangedThreshold(uint256 threshold);
    event ChangedExecutor(address indexed executor);
    event ExecutionSuccess(bytes32 indexed txHash, uint256 nonce);
    event Queued(bytes32 indexed txHash, uint256 nonce, uint256 eta);

    error InvalidSig();
    error Unauthorized();
    error InvalidConfig();
    error NotReady(uint256 eta);

    uint32 public delay;
    uint48 public nonce;
    uint16 public threshold;
    address public executor;
    address immutable factory = msg.sender;

    address[] owners;
    mapping(address account => bool) public isOwner;
    mapping(bytes32 txHash => uint256) public queued;

    modifier onlySelf() {
        require(msg.sender == address(this), Unauthorized());
        _;
    }

    constructor() payable {}

    function init(address[] calldata _owners, uint32 _delay, uint256 _threshold, address _executor) public payable {
        require(msg.sender == factory || msg.sender == address(this), Unauthorized());
        require(threshold == 0 && _threshold != 0 && _threshold <= _owners.length, InvalidConfig());
        if (_delay != 0) delay = _delay;
        if (_executor != address(0)) executor = _executor;
        threshold = uint16(_threshold);
        address prev;
        address owner;
        for (uint256 i; i != _owners.length; ++i) {
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
            require(_threshold != 0 && sigs.length == _threshold * 65, InvalidSig());
            uint256 o;
            address prev;
            address signer;
            for (uint256 i; i != _threshold; ++i) {
                o = i * 65;
                signer = ecrecover(safe, uint8(sigs[o + 64]), bytes32(sigs[o:o + 32]), bytes32(sigs[o + 32:o + 64]));
                require(signer != address(0) && isOwner[signer] && signer > prev, InvalidSig());
                prev = signer;
            }
            return this.isValidSignature.selector;
        }
    }

    function execute(address target, uint256 value, bytes calldata data, bytes calldata sigs) public payable {
        unchecked {
            (uint32 _delay, uint48 _nonce, uint16 _threshold, address _executor) = (delay, nonce++, threshold, executor);
            bytes32 hash = _txHash(target, value, data, _nonce);

            if (msg.sender != _executor) {
                uint256 o;
                address prev;
                address signer;
                require(_threshold != 0 && sigs.length == _threshold * 65, InvalidSig());
                for (uint256 i; i != _threshold; ++i) {
                    o = i * 65;
                    signer = ecrecover(hash, uint8(sigs[o + 64]), bytes32(sigs[o:o + 32]), bytes32(sigs[o + 32:o + 64]));
                    require(signer != address(0) && isOwner[signer] && signer > prev, InvalidSig());
                    prev = signer;
                }
            }

            if (_delay == 0 || msg.sender == _executor) {
                (bool ok, bytes memory ret) = target.call{value: value}(data);
                if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
                emit ExecutionSuccess(hash, _nonce);
            } else {
                uint256 eta = block.timestamp + _delay;
                queued[hash] = eta;
                emit Queued(hash, _nonce, eta);
            }
        }
    }

    function executeQueued(address target, uint256 value, bytes calldata data, uint48 _nonce) public payable {
        bytes32 hash = _txHash(target, value, data, _nonce);
        uint256 eta = queued[hash];
        require(eta != 0 && block.timestamp >= eta, NotReady(eta));
        delete queued[hash];
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
        emit ExecutionSuccess(hash, _nonce);
    }

    function _txHash(address target, uint256 value, bytes calldata data, uint48 _nonce)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Execute(address target,uint256 value,bytes data,uint48 nonce)"),
                        target,
                        value,
                        keccak256(data),
                        _nonce
                    )
                )
            )
        );
    }

    function delegateCall(address target, bytes calldata data) public payable onlySelf {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }

    function batch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas)
        public
        payable
        onlySelf
    {
        for (uint256 i; i != targets.length; ++i) {
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
        }
    }

    function addOwner(address _owner) public payable onlySelf {
        require(_owner != address(0) && !isOwner[_owner], InvalidConfig());
        isOwner[_owner] = true;
        owners.push(_owner);
        emit AddedOwner(_owner);
    }

    function removeOwner(address _owner) public payable onlySelf {
        uint256 len = owners.length;
        require(len > threshold && isOwner[_owner], InvalidConfig());
        isOwner[_owner] = false;
        for (uint256 i; i != len; ++i) {
            unchecked {
                if (owners[i] == _owner) {
                    owners[i] = owners[len - 1];
                    owners.pop();
                    break;
                }
            }
        }
        emit RemovedOwner(_owner);
    }

    function setDelay(uint32 _delay) public payable onlySelf {
        emit ChangedDelay(delay = _delay);
    }

    function setExecutor(address _executor) public payable onlySelf {
        emit ChangedExecutor(executor = _executor);
    }

    function setThreshold(uint256 _threshold) public payable onlySelf {
        require(_threshold != 0 && _threshold <= owners.length, InvalidConfig());
        threshold = uint16(_threshold);
        emit ChangedThreshold(_threshold);
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

    address public immutable implementation = address(new Multisig{salt: bytes32(0)}());

    constructor() payable {}

    /// @dev Create deterministic multisig wallet with PUSH0 and CREATE2.
    /// Adapted from Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibClone.sol).
    /// The salt must start with the zero address, or the caller, for front-running protection.
    function create(address[] calldata _owners, uint32 _delay, uint256 _threshold, address _executor, uint256 salt)
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
        Multisig(payable(wallet)).init(_owners, _delay, _threshold, _executor);
        emit Created(wallet);
    }
}
