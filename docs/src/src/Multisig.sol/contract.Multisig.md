# Multisig
[Git Source](https://github.com/z0r0z/multisig/blob/8708b4ffa2c639f2cc4a07f746205a2c3317d9b8/src/Multisig.sol)


## State Variables
### delay

```solidity
uint32 public delay
```


### nonce

```solidity
uint48 public nonce
```


### threshold

```solidity
uint16 public threshold
```


### executor

```solidity
address public executor
```


### factory

```solidity
address immutable factory = msg.sender
```


### owners

```solidity
address[] owners
```


### isOwner

```solidity
mapping(address account => bool) public isOwner
```


### queued

```solidity
mapping(bytes32 txHash => uint256) public queued
```


## Functions
### onlySelf


```solidity
modifier onlySelf() ;
```

### constructor


```solidity
constructor() payable;
```

### init


```solidity
function init(address[] calldata _owners, uint32 _delay, uint256 _threshold, address _executor) public payable;
```

### getOwners


```solidity
function getOwners() public view returns (address[] memory);
```

### DOMAIN_SEPARATOR


```solidity
function DOMAIN_SEPARATOR() public view returns (bytes32);
```

### isValidSignature


```solidity
function isValidSignature(bytes32 hash, bytes calldata sigs) public view returns (bytes4);
```

### execute


```solidity
function execute(address target, uint256 value, bytes calldata data, bytes calldata sigs) public payable;
```

### executeQueued


```solidity
function executeQueued(address target, uint256 value, bytes calldata data, uint48 _nonce) public payable;
```

### _txHash


```solidity
function _txHash(address target, uint256 value, bytes calldata data, uint48 _nonce)
    internal
    view
    returns (bytes32);
```

### delegateCall


```solidity
function delegateCall(address target, bytes calldata data) public payable onlySelf;
```

### batch


```solidity
function batch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas)
    public
    payable
    onlySelf;
```

### addOwner


```solidity
function addOwner(address _owner) public payable onlySelf;
```

### removeOwner


```solidity
function removeOwner(address _owner) public payable onlySelf;
```

### setDelay


```solidity
function setDelay(uint32 _delay) public payable onlySelf;
```

### setExecutor


```solidity
function setExecutor(address _executor) public payable onlySelf;
```

### setThreshold


```solidity
function setThreshold(uint256 _threshold) public payable onlySelf;
```

### receive


```solidity
receive() external payable;
```

### fallback

Handles all ERC721 and ERC1155 token safety callbacks.
Adapted from Solady (https://github.com/Vectorized/solady/blob/main/src/accounts/Receiver.sol)


```solidity
fallback() external payable;
```

## Events
### ChangedDelay

```solidity
event ChangedDelay(uint256 delay);
```

### AddedOwner

```solidity
event AddedOwner(address indexed owner);
```

### RemovedOwner

```solidity
event RemovedOwner(address indexed owner);
```

### ChangedThreshold

```solidity
event ChangedThreshold(uint256 threshold);
```

### ChangedExecutor

```solidity
event ChangedExecutor(address indexed executor);
```

### ExecutionSuccess

```solidity
event ExecutionSuccess(bytes32 indexed txHash, uint256 nonce);
```

### Queued

```solidity
event Queued(bytes32 indexed txHash, uint256 nonce, uint256 eta);
```

## Errors
### InvalidSig

```solidity
error InvalidSig();
```

### Unauthorized

```solidity
error Unauthorized();
```

### InvalidConfig

```solidity
error InvalidConfig();
```

### NotReady

```solidity
error NotReady(uint256 eta);
```

