# Multisig

Minimal EIP-712 multisig wallet. Deploys as minimal clones via `MultisigFactory`.

## Usage

```bash
forge build
forge test
```

## Contracts

**Multisig** — k-of-n multisig wallet. Owners submit EIP-712 signed transactions off-chain; anyone can relay `execute()` with the collected signatures (sorted by signer address, ascending). Supports EIP-1271 `isValidSignature`, ETH, ERC721, and ERC1155 receives. Owner/threshold management is self-governed.

**MultisigFactory** — Deploys deterministic PUSH0 minimal proxy clones via CREATE2. Call `create(owners, threshold, salt)` to deploy a new wallet.

## License

MIT
