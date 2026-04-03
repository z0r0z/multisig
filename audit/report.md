# Multisig Security Audit Report

**Date:** 2026-04-03 (updated)
**Previous:** 2026-04-02
**Target:** `src/Multisig.sol` (Multisig + MultisigFactory)
**Method:** Pashov Skills — 8-agent parallelized security audit (two passes)
**Solidity:** ^0.8.34

---

## Scope

| Contract | Lines | Description |
|---|---|---|
| `Multisig` | 1–240 | Threshold multisig with optional timelock, executor role, and pre/post guardian hooks |
| `MultisigFactory` | 242–277 | Minimal proxy (PUSH0 clone) factory with CREATE2 |

---

## Summary

| # | Severity | Title | Confidence | Agents | Status |
|---|----------|-------|------------|--------|--------|
| 1 | Medium | Pre-fund theft via zero-prefix CREATE2 salt front-running | 75 | 1 | Acknowledged — design tradeoff (use sender-bound salt for pre-fund) |
| 2 | Medium | Pre-execution hook fires before signature validation | 90 | 7 | Acknowledged — intentional guardian/ban-check pattern |
| 3 | Medium | Queued transactions had no cancellation mechanism | 80 | 7 | **Resolved** — `cancelQueued()` added (executor-only) |
| 4 | Low | `executeQueued` callable by anyone — no access control | 65 | 7 | Design choice — relayer compatibility |
| 5 | Low | Post-execution hook fires even when transaction is only queued | 75 | 2 | Acknowledged — intentional, allows guardian to veto queuing |
| 6 | Low | Both pre-hook and post-hook fire for crafted executor address | 75 | 5 | Acknowledged — intentional dual-hook design |
| L1 | Lead | Executor bypasses both signatures and timelock | — | 7 | By design — trusted module (Safe-like pattern) |
| L2 | Lead | Executor can burn nonces to invalidate owner signatures | — | 3 | By design — subset of executor trust |
| L3 | Lead | Unsafe uint16 downcast of threshold | — | 5 | Unreachable (65536+ owners infeasible) |
| L4 | Lead | Signature malleability (no low-s check in ecrecover) | — | 2 | Mitigated by sorted-signer ordering |
| L5 | Lead | uint32 nonce overflow in unchecked block | — | 2 | Impractical (~4B txs required) |
| L6 | Lead | Stale executor reference in post-hook | — | 1 | Accepted — atomic tx semantics limit impact |
| L7 | Lead | No reentrancy guard on execute (hook interaction) | — | 1 | Accepted — executor is trusted |
| L8 | Lead | Uninitialized implementation contract | — | 2 | Low risk |
| L9 | Lead | `batch()` missing array length validation | — | 2 | Solidity ABI decoder catches |
| L10 | Lead | `addOwner` breaks sorted-order invariant | — | 4 | Cosmetic — off-chain tooling only |
| L11 | Lead | `msg.value` not earmarked when transaction is queued | — | 1 | Design tradeoff |

---

## Findings

### [F-1] MEDIUM — Pre-fund theft via zero-prefix CREATE2 salt front-running [agents: 1]

**Contract:** MultisigFactory
**Function:** `create()` (line 261)
**Bug class:** front-running / pre-fund-theft

**Description:** The factory allows salts where `salt >> 96 == 0`, meaning any caller can deploy to the same deterministic address. If a user computes the address off-chain, pre-funds it with ETH, and uses a zero-prefix salt, an attacker can front-run the deployment with different owners and steal the pre-funded ETH.

**Proof:**
```solidity
// Line 261: zero-prefix salt allows anyone to use it
require(salt >> 96 == 0 || salt >> 96 == uint160(msg.sender), SaltDoesNotStartWith());
// salt >> 96 == 0 → no sender binding → any caller can deploy with this salt
```

**Gate evaluation:**
- Gate 1: Users can avoid this by using sender-bound salts. Speculative. CLEARS.
- Gate 2: Requires user to pre-fund AND use zero-prefix salt. Achievable (-10). CLEARS.
- Gate 3: Unprivileged attacker front-runs. CLEARS.
- Gate 4: Pre-funded ETH stolen — material loss. CONFIRMED.

**Confidence:** 75

**Developer response:** Acknowledged as a design tradeoff. Zero-prefix salts exist for gas-efficient open/relayer deploys where pre-funding is not expected. Sender-bound salts (`salt >> 96 == uint160(msg.sender)`) cover the pre-fund case. This mirrors Safe's philosophy of allowing permissionless deploys — Safe bakes init params into the salt (extra on-chain hashing cost), while this factory uses a cheaper raw salt with an opt-in sender-prefix guard. Both designs allow open deploys; the user chooses the appropriate salt type for their use case.

---

### [F-2] MEDIUM — Pre-execution hook fires before signature validation [agents: 7]

**Contract:** Multisig
**Function:** `execute()` (lines 111–115)
**Bug class:** pre-validation-external-call

**Description:** When the executor address has its top 2 bytes matching `0x1111` (line 113: `uint160(_executor) >> 144 == 0x1111`), an external call `Multisig(payable(_executor)).execute(target, value, data, sigs)` fires at line 114 BEFORE signature verification at lines 118–126. Any caller can forward arbitrary unvalidated parameters to the executor contract. If the executor is a Multisig where the calling contract is set as its executor, the forwarded call executes without signature validation on either side. EVM atomicity means the entire transaction reverts if the subsequent sig check fails, so state changes don't persist for unauthorized callers — but when `msg.sender == executor`, the sig check is skipped entirely and both the pre-hook call and local execution proceed.

**Confidence:** 90

**Developer response:** Acknowledged — this is the intentional guardian/ban-check pattern. The executor contract is a trusted guardian that needs to see (and potentially revert) transactions BEFORE they are authorized, acting as a blocklist or policy enforcer. The pre-auth ordering is by design.

---

### [F-3] MEDIUM — Queued transactions had no cancellation mechanism [agents: 7] — RESOLVED

**Contract:** Multisig
**Function:** `executeQueued()` (line 148)
**Bug class:** missing-safety-mechanism

**Description:** `executeQueued` has no access control — any address can execute a queued transaction once `block.timestamp >= eta`. There was no `cancelQueued` function. Once queued, a malicious transaction (from compromised-then-rotated signers) would execute irrevocably after the delay period. A cancel via `onlySelf` would itself be timelocked, making it useless — the malicious tx would execute before the cancel clears its own delay.

**Confidence:** 80

**Resolution:** Added `cancelQueued(bytes32 hash)` gated to the executor role. The executor can act immediately without signatures or timelock, making it the only role capable of emergency cancellation within the delay window. This is consistent with the executor's trust model as a privileged emergency key (similar to Safe modules).

```solidity
function cancelQueued(bytes32 hash) public payable {
    require(msg.sender == executor, Unauthorized());
    delete queued[hash];
}
```

**Test coverage:** `test_cancelQueued_executorCancels`, `test_cancelQueued_revertNotExecutor`, `test_cancelQueued_revertNoExecutorSet`.

---

### [F-4] LOW — `executeQueued` callable by anyone [agents: 7]

**Contract:** Multisig
**Function:** `executeQueued()` (line 148)
**Bug class:** missing-access-control

**Description:** `executeQueued` has no access control. Once a transaction's ETA has passed, any address can trigger execution. This enables MEV extraction on the execution and removes owners' ability to choose execution timing.

**Gate evaluation:** Gate 3 clears (unprivileged), but Gate 4 impact is typically dust-level (timing advantage, not direct fund theft). DEMOTE.

**Confidence:** 65

**Developer response:** Intentional for relayer compatibility — anyone can relay a queued transaction once the delay has passed. The new `cancelQueued` (executor-only) provides the emergency brake if needed.

---

### [F-5] LOW — Post-execution hook fires even when transaction is only queued [agents: 2]

**Contract:** Multisig
**Function:** `execute()` (lines 138–141)
**Bug class:** logic-error

**Description:** The post-hook at lines 138–141 fires unconditionally after the execute/queue branching logic. When `delay > 0` and the transaction is only queued (not executed), the post-hook still calls `executor.execute(target, value, data, sigs)`, forwarding the queued transaction's parameters to the executor contract.

**Confidence:** 75

**Developer response:** Acknowledged — intentional. Since the post-hook is in the same atomic transaction, the guardian can inspect the queued parameters and revert the entire transaction (including the queue write) if policy is violated. This acts as a veto on queuing itself.

---

### [F-6] LOW — Both pre-hook and post-hook fire for crafted executor address [agents: 5]

**Contract:** Multisig
**Function:** `execute()` (lines 111–115, 138–141)
**Bug class:** double-invocation

**Description:** The pre-hook (line 113: `uint160(_executor) >> 144 == 0x1111`) and post-hook (line 140: `uint160(_executor) & 0xFFFF == 0x1111`) check non-overlapping bits and are not mutually exclusive. An executor address satisfying both (e.g., `0x1111...1111`) triggers `executor.execute()` twice per transaction.

**Confidence:** 75

**Developer response:** Acknowledged — intentional dual-hook design. Pre-hook is for blocking/banning, post-hook is for notification/veto. Both firing for a guardian address is the intended behavior.

---

## Leads

_High-signal trails for manual review. Not scored._

- **[L1] Executor bypasses both signatures and timelock** — `Multisig.execute` — The executor skips signature verification (line 117) AND the timelock delay (line 130). A compromised executor key has unilateral, immediate control. **Assessment:** By design. The executor is an intentionally trusted module (Safe-like pattern). Users who set an executor accept this trust assumption. Consistent with the guardian architecture where the executor is a privileged emergency key.

- **[L2] Executor can burn nonces to invalidate owner signatures** — `Multisig.execute` — The executor can call `execute()` with dummy parameters to increment nonces, invalidating pre-signed owner transactions. **Assessment:** Subset of executor trust. If the executor is compromised, nonce griefing is the least concern — they can drain the wallet directly.

- **[L3] Unsafe uint16 downcast of threshold** — `Multisig.init` — `threshold = uint16(_threshold)` and `ownerCount = uint16(len)` silently truncate values above 65535. **Assessment:** Requires 65,536+ owners. Gas cost of writing that many storage slots exceeds any chain's block limit. Unreachable.

- **[L4] Signature malleability (no low-s check)** — `Multisig.isValidSignature` / `Multisig.execute` — Raw `ecrecover` without `s <= secp256k1n/2` check. Both `(v, r, s)` and `(v', r, n-s)` recover the same address. **Assessment:** The sorted-signer ordering (`signer > prev`) prevents internal double-counting. External protocols using signature bytes as dedup keys could be affected, but this is a downstream concern.

- **[L5] uint32 nonce overflow** — `Multisig.execute` — `nonce` is `uint32` incremented in `unchecked`, wrapping after ~4 billion executions. **Assessment:** Impractical on L1. On L2 with a compromised executor burning nonces, still requires billions of transactions at gas cost exceeding any economic incentive.

- **[L6] Stale executor reference in post-hook** — `Multisig.execute` — Executor is cached at function entry (line 110). If the executed transaction changes the executor via `setExecutor`, the post-hook uses the stale (old) address. **Assessment:** Accepted. The post-hook firing on the old executor during a single atomic tx that changes the executor is a known edge case with limited impact.

- **[L7] No reentrancy guard on execute** — `Multisig.execute` — Pre/post hooks and `target.call` enable reentrant `execute()` calls, each consuming a fresh nonce. **Assessment:** Accepted. The executor is trusted, and non-executor reentrant calls still require valid signatures for each new nonce.

- **[L8] Uninitialized implementation contract** — `MultisigFactory` — The implementation deployed by the factory constructor is never initialized. `init()` requires `msg.sender == factory`, preventing third-party initialization. Holds no funds by design.

- **[L9] `batch()` missing array length validation** — `Multisig.batch` — No check that `targets`, `values`, and `datas` arrays have equal lengths. Solidity's ABI decoder reverts on out-of-bounds access. UX issue only.

- **[L10] `addOwner` breaks sorted-order invariant** — `Multisig.addOwner` — `init()` enforces ascending address order but `addOwner()` prepends to the list head. On-chain signature verification is unaffected (checks ascending signature order, not list order). Off-chain tooling relying on `getOwners()` for signature assembly may need to sort independently.

- **[L11] `msg.value` not earmarked when transaction is queued** — `Multisig.execute` — ETH sent with a queued `execute()` call is absorbed into the contract's general balance. The queued transaction uses whatever balance exists at execution time. Design tradeoff — the multisig is expected to hold ETH.

---

## Changes Made

| Change | Commit | Description |
|--------|--------|-------------|
| `cancelQueued(bytes32)` | pending | Executor-only emergency cancellation for queued transactions. Resolves F-3. |

---

## Methodology

This audit was performed using the [Pashov Skills](https://github.com/pashov/skills) parallelized audit framework, adapted for Claude Code. Eight specialized agents were spawned in parallel, each focused on a distinct vulnerability class:

1. **Vector Scan** — Known attack patterns (reentrancy, replay, front-running, DoS)
2. **Math Precision** — Arithmetic, overflow, unsafe downcasts, precision loss
3. **Access Control** — Permission gaps, initialization, privilege escalation
4. **Economic Security** — Value extraction, griefing economics, MEV
5. **Execution Trace** — Parameter divergence, stale reads, encoding mismatches
6. **Invariant** — State couplings, conservation laws, boundary conditions
7. **Periphery** — Factory, assembly, fallback, infrastructure
8. **First Principles** — Implicit assumptions, temporal inconsistencies

Results were deduplicated by `group_key`, gate-evaluated per the Pashov judging framework (4 sequential gates: refutation, reachability, trigger, impact), and reviewed with the developer to assess design intent vs. vulnerability.

**Second pass (2026-04-03):** Re-ran the full 8-agent audit after the initial report. New findings related to the guardian hook mechanism (F-2, F-5, F-6) were identified and discussed with the developer. The missing cancellation mechanism (F-3) was resolved by adding `cancelQueued()`.

---

## Disclaimer

This report was generated using an AI-powered parallelized audit framework. AI-assisted audits are a preliminary check and should not be considered a substitute for a formal manual security review by experienced auditors. Always conduct thorough testing, formal verification, and professional audits before deploying smart contracts to mainnet.
