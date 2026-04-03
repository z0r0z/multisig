# IMultisig
[Git Source](https://github.com/z0r0z/multisig/blob/721bcd678965bd869b51578350a71b451e155085/src/mods/interfaces/IMultisig.sol)


## Functions
### execute


```solidity
function execute(address target, uint256 value, bytes calldata data, bytes calldata sigs) external payable;
```

### cancelQueued


```solidity
function cancelQueued(bytes32 hash) external payable;
```

### isOwner


```solidity
function isOwner(address account) external view returns (bool);
```

### threshold


```solidity
function threshold() external view returns (uint16);
```

### ownerCount


```solidity
function ownerCount() external view returns (uint16);
```

