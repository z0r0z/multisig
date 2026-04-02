# Multisig

Minimal EIP-712 multisig wallet with two deployment paths: factory clones and EIP-7702 EOA delegation.

## Usage

```bash
forge build
forge test
```

## Contract Multisig (Factory)

Deploy a standalone k-of-n multisig via `MultisigFactory`:

1. Call `MultisigFactory.create(owners, delay, threshold, executor, salt)` — deploys a deterministic minimal proxy clone and calls `init`.
2. Owners sign EIP-712 `Execute` messages off-chain.
3. Anyone relays `execute(target, value, data, sigs)` with signatures sorted by signer address (ascending).

The wallet is a standalone contract. If a `delay` is set, owner-signed transactions are queued and only executable after the delay via `executeQueued`. The executor (if set) bypasses both signature checks and the delay. Use `batch` and `delegateCall` via `execute(address(this), 0, abi.encodeCall(...), sigs)` to atomically bundle multiple calls or run arbitrary code in the wallet's context.

## Smart EOA (EIP-7702)

Turn an existing EOA into a multisig-enhanced account:

1. Submit a single `SET_CODE_TX` that delegates to the Multisig implementation **and** calls `init(owners, delay, threshold, executor)` on yourself in the same transaction.
2. Your EOA now supports `execute`, `batch`, and ERC-1271 `isValidSignature`.
3. Use `batch` to atomically manage configuration via `addOwner`, `removeOwner`, `setThreshold`, `setDelay`, and `setExecutor`.

The EOA private key remains a superuser — it can send regular transactions and revoke the delegation at any time. This path is best suited for personal wallets where the key holder wants co-signing, not shared custody.

## Executor Module

An optional `executor` address can be set at deployment or via `setExecutor`. The executor can call `execute` without signatures and bypasses the timelock delay, enabling two key patterns:

**Security Council** — A protocol's admin is a timelocked multisig (e.g. 3-of-5, 2-day delay). The executor is a separate security council multisig (e.g. 5-of-9). During an active exploit, the security council calls `execute` directly — no signatures from the admin owners needed, no delay. Owners can revoke the council at any time via `setExecutor(address(0))`.

**Social Recovery** — The executor is a guardian module (a multisig of trusted contacts). If the owner loses access to their keys, guardians call `execute` to immediately rotate owners via `addOwner`/`removeOwner`/`setThreshold`.

The trust assumption is explicit: the executor has full control. The timelock exists to protect against the *owners*, not the executor. If the executor is compromised, owners revoke it through the normal (timelocked) path.

## Contracts

**Multisig** — k-of-n multisig wallet with optional timelock and executor module. Supports EIP-1271 `isValidSignature`, `batch` execution, `delegateCall` for executing arbitrary code in the wallet's storage context, ETH, ERC-721, and ERC-1155 receives. Owner/threshold management is self-governed via `onlySelf` functions.

**MultisigFactory** — Deploys deterministic PUSH0 minimal proxy clones via CREATE2.

## License

MIT
