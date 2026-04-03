# Multisig

![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)

Minimal k-of-n multisig wallet with optional timelock, executor module, pre/post transaction guards, onchain approvals, batched execution, and delegatecall. Two deployment paths: factory clones and EIP-7702 EOA delegation. All mutable state (`delay`, `nonce`, `threshold`, `ownerCount`, `executor`) is packed into a single storage slot.

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
2. Owners sign EIP-712 `Execute` messages off-chain, approve onchain via `approve(hash, true)`, or submit directly as `msg.sender`.
3. Anyone relays `execute(target, value, data, sigs)` with signatures sorted by signer address (ascending).

The salt must start with `address(0)` (permissionless deploy) or `msg.sender` (sender-bound, for pre-funding). This follows the Solady `LibClone.checkStartsWith` pattern.

When `delay` is set, transactions are queued with an ETA and executed later via `executeQueued`. The executor can cancel queued transactions via `cancelQueued`. Use `batch` and `delegateCall` through `execute(address(this), ...)` to atomically bundle calls or run arbitrary code in the wallet's context.

The wallet supports ERC-721 and ERC-1155 token callbacks via the fallback function (`onERC721Received`, `onERC1155Received`, `onERC1155BatchReceived`).

### Factory Deployment with Module Setup

`MultisigFactory.createWithCalls(owners, delay, threshold, executor, salt, targets, values, datas)` deploys a wallet and atomically executes a list of calls to configure singleton modules. The factory temporarily sets itself as executor to bypass signatures during setup, then sets the real executor last.

```solidity
// Deploy wallet with AllowlistGuard configured
address[] memory targets = new address[](1);
uint256[] memory values = new uint256[](1);
bytes[] memory datas = new bytes[](1);
targets[0] = guard;
datas[0] = abi.encodeCall(AllowlistGuard.set, (usdc, IERC20.transfer.selector, true));
factory.createWithCalls(owners, 0, 2, guard, salt, targets, values, datas);
```

## EIP-7702 Deployment

Turn an existing EOA into a multisig-enhanced account:

1. Submit a `SET_CODE_TX` that delegates to the Multisig implementation and calls `init(owners, delay, threshold, executor)` in the same transaction.
2. The EOA now supports `execute`, `batch`, and ERC-1271 `isValidSignature`.
3. Manage configuration atomically via `batch`: `addOwner`, `removeOwner`, `setThreshold`, `setDelay`, `setExecutor`.

The EOA private key remains a superuser — it can send regular transactions and revoke the delegation at any time. Suited for personal wallets where the key holder wants co-signing, not shared custody.

## Signature Types

Each signer occupies a fixed 65-byte slot in the `sigs` array (`r[32] || s[32] || v[1]`), sorted ascending by signer address. Three approval methods:

| `v` | Type | How it works |
|---|---|---|
| `>= 27` | **ECDSA** | Standard off-chain signature. `ecrecover` recovers the signer. |
| `0` | **On-chain approval** | `r` = signer address (left-padded). Owner calls `approve(hash, true)` beforehand. |
| `0` | **Sender bypass** | `r` = signer address. If `msg.sender == signer`, no prior `approve` needed. |

The sender bypass means a 2-of-2 wallet needs only one ECDSA signature — the other owner submits the transaction and their `msg.sender` fills the second slot. For a k-of-n wallet, collect k-1 ECDSA signatures off-chain, then the final owner submits.

Owners can revoke an onchain approval with `approve(hash, false)` before the transaction reaches quorum.

Use `getTransactionHash(target, value, data, nonce)` to compute the EIP-712 digest for signing or approving.

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

## Modules

Singleton module contracts in `src/mods/` demonstrate common patterns — each is deployed once and serves all multisigs, keyed by `msg.sender`. Configure via `createWithCalls` at deployment or `execute` after.

| Module | Role | Safe/Zodiac Equivalent |
|---|---|---|
| **AllowlistGuard** | Pre-guard (vanity `0x1111` prefix) | Zodiac TransactionGuard |
| **SpendingAllowance** | Executor | Safe AllowanceModule |
| **SocialRecovery** | Executor | Safe SocialRecoveryModule |
| **DeadmanSwitch** | Post-guard + executor (vanity `0x1111` suffix) | Zodiac Dead Man's Switch |
| **CancelTx** | Executor | — (cancel at threshold, fast-forward unanimous, opt-in) |

## Comparison with Safe

| Feature | This Multisig | Safe |
|---|---|---|
| **Core LOC** | 318 (single file) | ~3,500 (multiple files) |
| **Runtime bytecode** | ~10 KB | ~23 KB |
| **Proxy clone size** | 45 bytes (PUSH0) | 45 bytes (EIP-1167) |
| **Storage: core state** | 1 slot (packed) | Multiple slots |
| **SLOAD/SSTORE for state** | 1 / 1 | Multiple |
| **Timelock** | Built-in (`delay`) | Modular (Zodiac Delay) |
| **Executor role** | Built-in | Modular (`execTransactionFromModule`) |
| **Batch execution** | Built-in (`batch`) | Composable (MultiSend) |
| **Delegate call** | Built-in (`delegateCall`) | Built-in (operation enum) |
| **EIP-712 / EIP-1271** | Built-in | Built-in |
| **Signature types** | ECDSA, onchain approval, sender bypass | ECDSA, EIP-1271, pre-approved hashes |
| **EIP-7702** | Native (dual-path init) | SafeEIP7702Proxy |
| **Module system** | Single-slot (`executor`) + singletons | Multi-module (linked list) |
| **Guard system** | Yes (vanity address encoding) | Yes (pre/post transaction hooks) |
| **CREATE2 factory** | Yes (sender-bound salt) | Yes |
| **Atomic module setup** | `createWithCalls` | `setup` delegatecall |

### Gas Benchmarks

This multisig: `forge test --mc GasTest -vv` (`gasleft()` snapshots, warm storage). Safe: `npm run benchmark` in [safe-smart-account](https://github.com/safe-global/safe-smart-account).

| Operation | This Multisig | Safe | Delta |
|---|---|---|---|
| **Deploy (proxy + init)** | | | |
| 1 owner | 142,024 | 166,375 | -15% |
| 2 owners | 164,796 | 189,886 | -13% |
| 3 owners | 187,569 | 213,385 | -12% |
| **ETH transfer** | | | |
| 1-of-1 | 43,550 | 58,142 | -25% |
| 2-of-2 | 47,826 | 65,193 | -27% |
| 2-of-3 | 47,826 | — | — |
| 3-of-3 | 52,104 | 72,293 | -28% |
| 3-of-5 | 52,104 | 72,281 | -28% |
| **Executor (no sigs)** | 40,932 | — | — |
| **Queue (delay)** | 35,810 | — | — |
| **Execute queued** | 38,642 | — | — |
| **Batch 3 ETH transfers** | 65,689 | — | — |

- Execution is 25-28% cheaper due to single-slot state packing. Each additional signer adds ~4,300 gas (`ecrecover` + `isOwner` SLOAD).
- Executor, timelock, and batch are built-in. Safe requires external modules and MultiSend.
- Deployment is 12-15% cheaper across all owner counts — the sorted linked list requires only one storage write per owner.
- Safe's overhead pays for guard hooks, gas refunds, EIP-1271 contract signatures, and fallback handler dispatch.

Safe composes features as separate contracts (modules, guards, fallback handlers). This multisig ships them as built-in primitives in a single file with all hot-path state in one slot. The executor doubles as a pre/post transaction guard via vanity address encoding — zero additional storage. Point the executor at a router contract to dispatch across multiple sub-modules without per-wallet storage overhead.

## License

MIT
