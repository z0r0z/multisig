# Multisig

Minimal EIP-712 multisig wallet. Deploys as minimal clones via `MultisigFactory`.

## Usage

```bash
forge build
forge test
```

## Contracts

**Multisig** — k-of-n multisig wallet. Owners submit EIP-712 signed transactions off-chain; anyone can relay `execute()` with the collected signatures (sorted by signer address, ascending). Supports ETH, ERC721, and ERC1155 receives. Owner/threshold management is self-governed.

**MultisigFactory** — Deploys PUSH0 minimal proxy clones of a locked implementation. Call `create(owners, threshold)` to deploy a new wallet.

## License

MIT
