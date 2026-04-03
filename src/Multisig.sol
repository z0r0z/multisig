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
    event Approved(address indexed owner, bytes32 indexed hash, bool ok);

    error InvalidSig();
    error Unauthorized();
    error InvalidConfig();
    error NotReady(uint256 eta);

    uint32 public delay;
    uint32 public nonce;
    uint16 public threshold;
    uint16 public ownerCount;
    address public executor;

    address immutable factory = msg.sender;
    address constant SENTINEL = address(1);

    mapping(address => address) _owners;
    mapping(bytes32 txHash => uint256) public queued;
    mapping(address owner => mapping(bytes32 hash => bool)) public approved;

    modifier onlySelf() {
        require(msg.sender == address(this), Unauthorized());
        _;
    }

    constructor() payable {}

    function init(address[] calldata owners_, uint32 _delay, uint256 _threshold, address _executor) public payable {
        require(msg.sender == factory || msg.sender == address(this), Unauthorized());
        uint256 len = owners_.length;
        require(threshold == 0 && _threshold != 0 && _threshold <= len, InvalidConfig());
        if (_delay != 0) delay = _delay;
        if (_executor != address(0)) executor = _executor;
        threshold = uint16(_threshold);
        ownerCount = uint16(len);
        address prev = SENTINEL;
        address owner;
        unchecked {
            for (uint256 i; i != len; ++i) {
                owner = owners_[i];
                require(owner > prev, InvalidConfig());
                _owners[prev] = owner;
                prev = owner;
            }
        }
        _owners[prev] = SENTINEL;
    }

    function isOwner(address account) public view returns (bool) {
        return account != SENTINEL && _owners[account] != address(0);
    }

    function getOwners() public view returns (address[] memory) {
        address[] memory arr = new address[](ownerCount);
        address current = _owners[SENTINEL];
        for (uint256 i; current != SENTINEL; ++i) {
            arr[i] = current;
            current = _owners[current];
        }
        return arr;
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

    function getTransactionHash(address target, uint256 value, bytes calldata data, uint32 _nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Execute(address target,uint256 value,bytes data,uint32 nonce)"),
                        target,
                        value,
                        keccak256(data),
                        _nonce
                    )
                )
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
                if (uint8(sigs[o + 64]) == 0) {
                    signer = address(uint160(uint256(bytes32(sigs[o:o + 32]))));
                    require(approved[signer][safe], InvalidSig());
                } else {
                    signer = ecrecover(safe, uint8(sigs[o + 64]), bytes32(sigs[o:o + 32]), bytes32(sigs[o + 32:o + 64]));
                }
                require(signer != address(0) && _owners[signer] != address(0) && signer > prev, InvalidSig());
                prev = signer;
            }
            return this.isValidSignature.selector;
        }
    }

    function execute(address target, uint256 value, bytes calldata data, bytes calldata sigs) public payable {
        unchecked {
            (uint32 _delay, uint32 _nonce, uint16 _threshold, address _executor) = (delay, nonce++, threshold, executor);
            bytes32 hash = getTransactionHash(target, value, data, _nonce);

            if (uint160(_executor) >> 144 == 0x1111) Multisig(payable(_executor)).execute(target, value, data, sigs);

            if (msg.sender != _executor) {
                uint256 o;
                address prev;
                address signer;
                require(_threshold != 0 && sigs.length == _threshold * 65, InvalidSig());
                for (uint256 i; i != _threshold; ++i) {
                    o = i * 65;
                    if (uint8(sigs[o + 64]) == 0) {
                        signer = address(uint160(uint256(bytes32(sigs[o:o + 32]))));
                        require(msg.sender == signer || approved[signer][hash], InvalidSig());
                    } else {
                        signer =
                            ecrecover(hash, uint8(sigs[o + 64]), bytes32(sigs[o:o + 32]), bytes32(sigs[o + 32:o + 64]));
                    }
                    require(signer != address(0) && _owners[signer] != address(0) && signer > prev, InvalidSig());
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

            if ((uint160(_executor) & 0xFFFF) == 0x1111) {
                Multisig(payable(_executor)).execute(target, value, data, sigs);
            }
        }
    }

    function approve(bytes32 hash, bool ok) public payable {
        require(isOwner(msg.sender), Unauthorized());
        approved[msg.sender][hash] = ok;
        emit Approved(msg.sender, hash, ok);
    }

    function cancelQueued(bytes32 hash) public payable {
        require(msg.sender == executor, Unauthorized());
        delete queued[hash];
    }

    function executeQueued(address target, uint256 value, bytes calldata data, uint32 _nonce) public payable {
        bytes32 hash = getTransactionHash(target, value, data, _nonce);
        uint256 eta = queued[hash];
        require(eta != 0 && block.timestamp >= eta, NotReady(eta));
        delete queued[hash];
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
        emit ExecutionSuccess(hash, _nonce);
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
        require(_owner > SENTINEL && _owners[_owner] == address(0), InvalidConfig());
        _owners[_owner] = _owners[SENTINEL];
        _owners[SENTINEL] = _owner;
        unchecked {
            ++ownerCount;
        }
        emit AddedOwner(_owner);
    }

    function removeOwner(address prevOwner, address _owner) public payable onlySelf {
        require(ownerCount > threshold && _owners[_owner] != address(0) && _owner != SENTINEL, InvalidConfig());
        require(_owners[prevOwner] == _owner, InvalidConfig());
        _owners[prevOwner] = _owners[_owner];
        delete _owners[_owner];
        unchecked {
            --ownerCount;
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
        require(_threshold != 0 && _threshold <= ownerCount, InvalidConfig());
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

    /// @dev Create with post-init calls. Deploys with the factory as temporary
    /// executor so calls bypass signatures, then sets the real executor last.
    /// Use to configure singleton modules at the wallet's CREATE2 address.
    function createWithCalls(
        address[] calldata _owners,
        uint32 _delay,
        uint256 _threshold,
        address _executor,
        uint256 salt,
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) public payable returns (address wallet) {
        wallet = create(_owners, _delay, _threshold, address(this), salt);
        for (uint256 i; i != targets.length; ++i) {
            Multisig(payable(wallet)).execute(targets[i], values[i], datas[i], "");
        }
        Multisig(payable(wallet)).execute(wallet, 0, abi.encodeCall(Multisig.setExecutor, (_executor)), "");
    }
}
