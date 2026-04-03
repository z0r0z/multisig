# Multisig

![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)

Minimal k-of-n multisig wallet with optional timelock, executor module, pre/post transaction guards, batched execution, and delegatecall. Two deployment paths: factory clones and EIP-7702 EOA delegation. All mutable state (`delay`, `nonce`, `threshold`, `ownerCount`, `executor`) is packed into a single storage slot.

![Explainer](explainer.svg)

![Architecture](diagram.svg)

## Usage

```bash
forge build
forge test
```

## Factory Deployment

Deploy a standalone multisig via `MultisigFactory`:

1. `MultisigFactory.create(owners, delay, threshold, executor, salt)` — deploys a deterministic PUSH0 minimal proxy clone and calls `init`.
2. Owners sign EIP-712 `Execute` messages off-chain.
3. Anyone relays `execute(target, value, data, sigs)` with signatures sorted by signer address (ascending).

The salt must start with `address(0)` (permissionless deploy) or `msg.sender` (sender-bound, for pre-funding). This follows the Solady `LibClone.checkStartsWith` pattern.

When `delay` is set, transactions are queued with an ETA and executed later via `executeQueued`. The executor can cancel queued transactions via `cancelQueued`. Use `batch` and `delegateCall` through `execute(address(this), ...)` to atomically bundle calls or run arbitrary code in the wallet's context.

The wallet supports ERC-721 and ERC-1155 token callbacks via the fallback function (`onERC721Received`, `onERC1155Received`, `onERC1155BatchReceived`).

## EIP-7702 Deployment

Turn an existing EOA into a multisig-enhanced account:

1. Submit a `SET_CODE_TX` that delegates to the Multisig implementation and calls `init(owners, delay, threshold, executor)` in the same transaction.
2. The EOA now supports `execute`, `batch`, and ERC-1271 `isValidSignature`.
3. Manage configuration atomically via `batch`: `addOwner`, `removeOwner`, `setThreshold`, `setDelay`, `setExecutor`.

The EOA private key remains a superuser — it can send regular transactions and revoke the delegation at any time. Suited for personal wallets where the key holder wants co-signing, not shared custody.

## Executor

An optional `executor` address bypasses both signature verification and timelock delay, enabling two patterns:

**Security Council** — A protocol's admin is a timelocked multisig (e.g. 3-of-5, 2-day delay). The executor is a separate security council (e.g. 5-of-9). During an active exploit, the council calls `execute` directly — no owner signatures, no delay. Owners revoke via `setExecutor(address(0))`.

**Social Recovery** — The executor is a guardian multisig (trusted contacts). If the owner loses their keys, guardians call `execute` to rotate owners via `addOwner`/`removeOwner`/`setThreshold`.

The executor has full control by design. The timelock gives stakeholders an exit window against the *owners* — the executor operates outside it. If the executor is compromised, owners revoke it through the normal timelocked path.

### Guard Mode

The executor doubles as a transaction guard when deployed to a vanity address. Guard behavior is encoded in the address itself — no extra storage, no new functions:

| Leading 2 bytes | Trailing 2 bytes | Behavior |
|---|---|---|
| `0x1111` | any | Pre-transaction guard (called before execution) |
| any | `0x1111` | Post-transaction guard (called after execution) |
| `0x1111` | `0x1111` | Both pre and post guard |
| other | other | Plain executor (no guard calls) |

The guard receives the same `execute(target, value, data, sigs)` payload as the multisig — it can inspect the transaction and revert to block it, or no-op to allow. Mining a 4-byte vanity address (2 leading + 2 trailing) is comparable to mining a 4-byte prefix, feasible in minutes on a GPU.

## Comparison with Safe

| Feature | This Multisig | Safe |
|---|---|---|
| **Core LOC** | 281 (single file) | ~3,500 (multiple files) |
| **Runtime bytecode** | ~9.2 KB | ~23 KB |
| **Proxy clone size** | 45 bytes (PUSH0) | 45 bytes (EIP-1167) |
| **Storage: core state** | 1 slot (packed) | Multiple slots |
| **SLOAD/SSTORE for state** | 1 / 1 | Multiple |
| **Timelock** | Built-in (`delay`) | Modular (Zodiac Delay) |
| **Executor role** | Built-in | Modular (`execTransactionFromModule`) |
| **Batch execution** | Built-in (`batch`) | Composable (MultiSend) |
| **Delegate call** | Built-in (`delegateCall`) | Built-in (operation enum) |
| **EIP-712 / EIP-1271** | Built-in | Built-in |
| **Signature types** | ECDSA only | ECDSA, EIP-1271, pre-approved hashes |
| **EIP-7702** | Native (dual-path init) | SafeEIP7702Proxy |
| **Module system** | Single-slot (`executor`) | Multi-module (linked list) |
| **Guard system** | Yes (vanity address encoding) | Yes (pre/post transaction hooks) |
| **CREATE2 factory** | Yes (sender-bound salt) | Yes |

### Gas Benchmarks

This multisig: `forge test --mc GasTest -vv` (`gasleft()` snapshots, warm storage). Safe: `npm run benchmark` in [safe-smart-account](https://github.com/safe-global/safe-smart-account).

| Operation | This Multisig | Safe | Delta |
|---|---|---|---|
| **Deploy (proxy + init)** | | | |
| 1 owner | 141,930 | 166,375 | -15% |
| 2 owners | 164,702 | 189,886 | -13% |
| 3 owners | 187,475 | 213,385 | -12% |
| **ETH transfer** | | | |
| 1-of-1 | 43,421 | 58,142 | -25% |
| 2-of-2 | 47,613 | 65,193 | -27% |
| 2-of-3 | 47,613 | — | — |
| 3-of-3 | 51,807 | 72,293 | -28% |
| 3-of-5 | 51,807 | 72,281 | -28% |
| **Executor (no sigs)** | 40,887 | — | — |
| **Queue (delay)** | 35,597 | — | — |
| **Execute queued** | 38,664 | — | — |
| **Batch 3 ETH transfers** | 65,498 | — | — |

- Execution is 25-28% cheaper due to single-slot state packing. Each additional signer adds ~4,200 gas (`ecrecover` + `isOwner` SLOAD).
- Executor, timelock, and batch are built-in. Safe requires external modules and MultiSend.
- Deployment is 12-15% cheaper across all owner counts — the sorted linked list requires only one storage write per owner.
- Safe's overhead pays for guard hooks, gas refunds, multiple signature types, and fallback handler dispatch.

Safe composes features as separate contracts (modules, guards, fallback handlers). This multisig ships them as built-in primitives in a single file with all hot-path state in one slot. The executor doubles as a pre/post transaction guard via vanity address encoding — zero additional storage. Point the executor at a router contract to dispatch across multiple sub-modules without per-wallet storage overhead.

## License

MIT
