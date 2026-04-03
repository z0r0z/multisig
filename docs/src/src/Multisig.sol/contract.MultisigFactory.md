# MultisigFactory
[Git Source](https://github.com/z0r0z/multisig/blob/ba5a100b267602209ab0c55c94670979e30904c1/src/Multisig.sol)


## State Variables
### implementation

```solidity
address public immutable implementation = address(new Multisig{salt: bytes32(0)}())
```


## Functions
### constructor


```solidity
constructor() payable;
```

### create

Create deterministic multisig wallet with PUSH0 and CREATE2.
Adapted from Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibClone.sol).
The salt must start with the zero address, or the caller, for front-running protection.


```solidity
function create(address[] calldata _owners, uint32 _delay, uint256 _threshold, address _executor, uint256 salt)
    public
    payable
    returns (address wallet);
```

## Events
### Created

```solidity
event Created(address indexed wallet);
```

## Errors
### DeploymentFailed

```solidity
error DeploymentFailed();
```

### SaltDoesNotStartWith

```solidity
error SaltDoesNotStartWith();
```

