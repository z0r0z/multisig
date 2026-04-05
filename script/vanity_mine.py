#!/usr/bin/env python3
"""
Mine CREATE2 vanity addresses for contracts via SafeSummoner.

Usage:
  python3 script/vanity_mine.py <ContractName> [--prefix PREFIX] [--total TOTAL]

Examples:
  python3 script/vanity_mine.py MultisigFactory --prefix 00000000
  python3 script/vanity_mine.py DeadmanSwitch --prefix 1111
  python3 script/vanity_mine.py AllowlistGuard --prefix 1111
  python3 script/vanity_mine.py SocialRecovery
  python3 script/vanity_mine.py SpendingAllowance
  python3 script/vanity_mine.py TimelockExecutor

Process:
1. The script auto-derives the init code hash via `forge inspect`.
2. Searches in parallel across all CPU cores for a CREATE2 salt.
3. Writes results to vanity_findings.md.

Verify any finding:
  cast create2 --deployer 0x00000000004473e1f31C8266612e7FD5504e6f2a \
    --salt <SALT> --init-code-hash <HASH>

Notes:
- Deployer is SafeSummoner (0x00000000004473e1f31C8266612e7FD5504e6f2a)
- 4 zero bytes = 1-in-2^32 (~4.3B), 2 bytes = 1-in-2^16 (~65K)
- At ~1.3M salts/s (Python, 8 cores), 4 zero bytes ~55 min average
"""

from Crypto.Hash import keccak
import multiprocessing as mp
import subprocess, argparse, time, os, sys

# --- Config ---
DEPLOYER = bytes.fromhex('00000000004473e1f31C8266612e7FD5504e6f2a')
CHUNK = 50_000_000
FINDINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vanity_findings.md')


def get_init_code_hash(contract_name):
    """Derive init code hash from forge inspect."""
    result = subprocess.run(
        ['forge', 'inspect', contract_name, 'bytecode'],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error: forge inspect failed for {contract_name}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    bytecode = result.stdout.strip()
    if bytecode.startswith('0x'):
        bytecode = bytecode[2:]
    raw = bytes.fromhex(bytecode)
    return keccak.new(digest_bits=256, data=raw).digest()


def parse_prefix(prefix_hex):
    """Parse prefix, supporting both leading and trailing match."""
    return bytes.fromhex(prefix_hex)


def search(args):
    start, end, init_hash, prefix, match_end = args
    results = []
    plen = len(prefix)
    for i in range(start, end):
        salt = i.to_bytes(32, 'big')
        data = b'\xff' + DEPLOYER + salt + init_hash
        h = keccak.new(digest_bits=256, data=data).digest()
        addr = h[12:32]
        if match_end:
            if addr[20 - plen:] == prefix:
                results.append((i, salt.hex(), addr.hex()))
        else:
            if addr[:plen] == prefix:
                results.append((i, salt.hex(), addr.hex()))
    return results


def write_findings(contract_name, init_hash, prefix_hex, match_end, results):
    """Append results to vanity_findings.md."""
    match_type = "trailing" if match_end else "leading"
    header = f"\n## {contract_name}\n\n"
    header += f"PREFIX: 0x{prefix_hex} ({match_type})\n"
    header += f"Deployer: SafeSummoner (0x{DEPLOYER.hex()})\n"
    header += f"InitCodeHash: 0x{init_hash.hex()}\n\n"
    header += "| # | Address | Salt | Nonce |\n"
    header += "|---|---------|------|-------|\n"

    rows = ""
    for idx, (nonce, salt, addr) in enumerate(sorted(results), 1):
        rows += f"| {idx} | `0x{addr}` | `0x{salt}` | {nonce} |\n"

    with open(FINDINGS_FILE, 'a') as f:
        f.write(header + rows)
    print(f"\nAppended {len(results)} result(s) to {FINDINGS_FILE}")


def main():
    parser = argparse.ArgumentParser(description='Mine CREATE2 vanity addresses via SafeSummoner')
    parser.add_argument('contract', help='Contract name (e.g. MultisigFactory, DeadmanSwitch)')
    parser.add_argument('--prefix', default='00000000', help='Hex prefix to match (default: 00000000)')
    parser.add_argument('--trailing', action='store_true', help='Match trailing bytes instead of leading')
    parser.add_argument('--total', type=int, default=5_000_000_000, help='Total salts to search (default: 5B)')
    args = parser.parse_args()

    init_hash = get_init_code_hash(args.contract)
    prefix = parse_prefix(args.prefix)
    ncpu = mp.cpu_count()

    print(f"Contract:       {args.contract}")
    print(f"Init code hash: 0x{init_hash.hex()}")
    print(f"Deployer:       0x{DEPLOYER.hex()}")
    print(f"Target prefix:  0x{args.prefix} ({'trailing' if args.trailing else 'leading'})")
    print(f"Searching {args.total:,} salts across {ncpu} workers...", flush=True)

    chunks = [(s, min(s + CHUNK, args.total), init_hash, prefix, args.trailing)
              for s in range(0, args.total, CHUNK)]

    start_t = time.time()
    all_results = []
    with mp.Pool(ncpu) as pool:
        for chunk_results in pool.imap_unordered(search, chunks):
            if chunk_results:
                all_results.extend(chunk_results)
                for nonce, salt, addr in chunk_results:
                    print(f"MATCH: nonce={nonce} salt=0x{salt} address=0x{addr}", flush=True)

    elapsed = time.time() - start_t
    rate = args.total / elapsed if elapsed > 0 else 0
    print(f"\nSearched {args.total:,} salts in {elapsed:.1f}s ({rate:,.0f} salts/s)")

    if all_results:
        all_results.sort()
        print(f"Found {len(all_results)} match(es)!")
        for nonce, salt, addr in all_results:
            print(f"  nonce={nonce} salt=0x{salt} address=0x{addr}")
        write_findings(args.contract, init_hash, args.prefix, args.trailing, all_results)
    else:
        print("No matches found. Try running again or increasing --total.")


if __name__ == '__main__':
    main()
