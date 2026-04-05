# IMultisig
[Git Source](https://github.com/z0r0z/multisig/blob/88f2fd9c70fcd2f83b9d61859bb5b7eeef042d87/src/mods/interfaces/IMultisig.sol)


## Functions
### nonce


```solidity
function nonce() external view returns (uint32);
```

### threshold


```solidity
function threshold() external view returns (uint16);
```

### ownerCount


```solidity
function ownerCount() external view returns (uint16);
```

### isOwner


```solidity
function isOwner(address account) external view returns (bool);
```

### approved


```solidity
function approved(address owner, bytes32 hash) external view returns (bool);
```

### cancelQueued


```solidity
function cancelQueued(bytes32 hash) external payable;
```

### getTransactionHash


```solidity
function getTransactionHash(address target, uint256 value, bytes calldata data, uint32 _nonce)
    external
    view
    returns (bytes32);
```

### execute


```solidity
function execute(address target, uint256 value, bytes calldata data, bytes calldata sigs) external payable;
```

