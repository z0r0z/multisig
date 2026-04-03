# CancelTx
[Git Source](https://github.com/z0r0z/multisig/blob/721bcd678965bd869b51578350a71b451e155085/src/mods/CancelTx.sol)

Executor module for queued transaction management. Cancel requires
threshold approvals (symmetric with signing). Fast-forward requires
all owners (unanimous) since it bypasses the timelock protection.
Fast-forward is opt-in — the multisig must call enableForward(true).
Singleton — one deployment serves all multisigs.


## State Variables
### cancelVoted

```solidity
mapping(address multisig => mapping(bytes32 hash => mapping(address owner => bool))) public cancelVoted
```


### cancelVotes

```solidity
mapping(address multisig => mapping(bytes32 hash => uint256)) public cancelVotes
```


### forwardEnabled

```solidity
mapping(address multisig => bool) public forwardEnabled
```


### forwardVoted

```solidity
mapping(address multisig => mapping(bytes32 id => mapping(address owner => bool))) public forwardVoted
```


### forwardVotes

```solidity
mapping(address multisig => mapping(bytes32 id => uint256)) public forwardVotes
```


## Functions
### constructor


```solidity
constructor() payable;
```

### enableForward


```solidity
function enableForward(bool enabled) public;
```

### cancel

Owners approve cancellation of a queued tx. Auto-cancels at threshold.


```solidity
function cancel(address multisig, bytes32 hash) public;
```

### forward

Owners approve immediate execution, bypassing timelock. Auto-executes when all owners have approved.


```solidity
function forward(address multisig, address target, uint256 value, bytes calldata data) public;
```

## Events
### Cancelled

```solidity
event Cancelled(address indexed multisig, bytes32 indexed hash);
```

### Forwarded

```solidity
event Forwarded(address indexed multisig, bytes32 indexed id);
```

### ForwardEnabled

```solidity
event ForwardEnabled(address indexed multisig, bool enabled);
```

### Voted

```solidity
event Voted(address indexed multisig, bytes32 indexed id, address indexed owner);
```

## Errors
### Unauthorized

```solidity
error Unauthorized();
```

