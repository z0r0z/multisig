# AllowlistGuard
[Git Source](https://github.com/z0r0z/multisig/blob/88f2fd9c70fcd2f83b9d61859bb5b7eeef042d87/src/mods/AllowlistGuard.sol)

Pre-transaction guard that whitelists (target, selector) pairs.
Deploy at a vanity address with leading 0x1111 to activate as pre-guard.
Singleton — one deployment serves all multisigs, keyed by msg.sender.


## State Variables
### allowed

```solidity
mapping(address multisig => mapping(address target => mapping(bytes4 sel => bool))) public allowed
```


## Functions
### constructor


```solidity
constructor() payable;
```

### execute

Called by multisig as pre-guard. Calls targeting the guard itself
are always allowed so owners can configure the allowlist after activation.
Plain ETH transfers (empty calldata) require allowlisting bytes4(0).


```solidity
function execute(address target, uint256, bytes calldata data, bytes calldata) public payable;
```

### set


```solidity
function set(address target, bytes4 sel, bool ok) public;
```

## Events
### AllowlistSet

```solidity
event AllowlistSet(address indexed multisig, address indexed target, bytes4 sel, bool allowed);
```

## Errors
### NotAllowed

```solidity
error NotAllowed();
```

### Unauthorized

```solidity
error Unauthorized();
```

