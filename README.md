# Multisig

Minimal EIP-712 multisig wallet with two deployment paths: factory clones and EIP-7702 EOA delegation.

## Usage

```bash
forge build
forge test
```

## Contract Multisig (Factory)

Deploy a standalone k-of-n multisig via `MultisigFactory`:

1. Call `MultisigFactory.create(owners, threshold, salt)` — deploys a deterministic minimal proxy clone and calls `init`.
2. Owners sign EIP-712 `Execute` messages off-chain.
3. Anyone relays `execute(target, value, data, sigs)` with signatures sorted by signer address (ascending).

The wallet is a standalone contract. No single key can bypass the threshold.

## Smart EOA (EIP-7702)

Turn an existing EOA into a multisig-enhanced account:

1. Submit a single `SET_CODE_TX` that delegates to the Multisig implementation **and** calls `init(owners, threshold)` on yourself in the same transaction.
2. Your EOA now supports `execute`, `batch`, and ERC-1271 `isValidSignature`.
3. Use `batch` to atomically manage owners/threshold via `addOwner`, `removeOwner`, and `setThreshold`.

The EOA private key remains a superuser — it can send regular transactions and revoke the delegation at any time. This path is best suited for personal wallets where the key holder wants co-signing, not shared custody.

## Contracts

**Multisig** — k-of-n multisig wallet. Supports EIP-1271 `isValidSignature`, `batch` execution, ETH, ERC-721, and ERC-1155 receives. Owner/threshold management is self-governed via `onlySelf` functions.

**MultisigFactory** — Deploys deterministic PUSH0 minimal proxy clones via CREATE2.

## License

MIT
