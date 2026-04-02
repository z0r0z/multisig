# Multisig Security Audit Report

**Date:** 2026-04-02
**Target:** `src/Multisig.sol` (Multisig + MultisigFactory)
**Method:** Pashov Skills — 8-agent parallelized security audit
**Solidity:** ^0.8.34

---

## Scope

| Contract | Lines | Description |
|---|---|---|
| `Multisig` | 1–218 | Threshold multisig with optional timelock and executor role |
| `MultisigFactory` | 220–254 | Minimal proxy (PUSH0 clone) factory with CREATE2 |

---

## Summary

| # | Severity | Title | Confidence | Agents | Status |
|---|----------|-------|------------|--------|--------|
| 1 | Medium | Pre-fund theft via zero-prefix CREATE2 salt front-running | 75 | 1 | Confirmed |
| 2 | Low | `executeQueued` callable by anyone — no access control | 65 | 4 | Design choice |
| L1 | Lead | Executor is a single point of total compromise | — | 6 | By design |
| L2 | Lead | No cancellation mechanism for queued transactions | — | 4 | By design (cancel would also be timelocked) |
| L3 | Lead | Unsafe uint16 downcast of threshold | — | 5 | Unreachable (65536+ owners infeasible) |
| L4 | Lead | Executor can burn nonces to invalidate owner signatures | — | 3 | Trust assumption |
| L5 | Lead | Uninitialized implementation contract | — | 2 | Low risk |
| L6 | Lead | `batch()` missing array length validation | — | 2 | Solidity ABI decoder catches |
| L7 | Lead | `removeOwner` breaks sorted-order invariant | — | 4 | Cosmetic |
| L8 | Lead | `msg.value` not earmarked when transaction is queued | — | 1 | Design tradeoff |

---

## Findings

### [F-1] MEDIUM — Pre-fund theft via zero-prefix CREATE2 salt front-running [agents: 1]

**Contract:** MultisigFactory
**Function:** `create()` (line 239)
**Bug class:** front-running / pre-fund-theft

**Description:** The factory allows salts where `salt >> 96 == 0`, meaning any caller can deploy to the same deterministic address. If a user computes the address off-chain, pre-funds it with ETH, and uses a zero-prefix salt, an attacker can front-run the deployment with different owners and steal the pre-funded ETH.

**Proof:**
```solidity
// Line 239: zero-prefix salt allows anyone to use it
require(salt >> 96 == 0 || salt >> 96 == uint160(msg.sender), SaltDoesNotStartWith());
// salt >> 96 == 0 → no sender binding → any caller can deploy with this salt
```

**Gate evaluation:**
- Gate 1: Users can avoid this by using sender-bound salts. Speculative. CLEARS.
- Gate 2: Requires user to pre-fund AND use zero-prefix salt. Achievable (-10). CLEARS.
- Gate 3: Unprivileged attacker front-runs. CLEARS.
- Gate 4: Pre-funded ETH stolen — material loss. CONFIRMED.

**Confidence:** 75

**Recommendation:** Document that zero-prefix salts must never be used when pre-funding a deterministic address. Users should always use sender-bound salts (`salt >> 96 == uint160(msg.sender)`) for any deployment where ETH is sent to the predicted address before `create()` is called.

---

### [F-2] LOW — `executeQueued` callable by anyone [agents: 4]

**Contract:** Multisig
**Function:** `executeQueued()` (lines 120–128)
**Bug class:** missing-access-control

**Description:** `executeQueued` has no access control. Once a transaction's ETA has passed, any address can trigger execution. This enables MEV extraction on the execution and removes owners' ability to choose execution timing.

**Gate evaluation:** Gate 3 clears (unprivileged), but Gate 4 impact is typically dust-level (timing advantage, not direct fund theft). DEMOTE.

**Confidence:** 65

**Note:** This is likely intentional for relayer compatibility — anyone can relay a queued transaction once the delay has passed. Tests confirm this behavior (`test_timelock_executeQueuedAnyone`).

---

## Leads

### [L1] Executor is a single point of total compromise [agents: 6]

The executor role bypasses both signature verification (line 95) and the timelock delay (line 108). A compromised executor key can immediately execute arbitrary transactions without any owner signatures.

**Assessment:** This is by design. The executor is an intentionally trusted hot key for fast execution. Since it is already trusted to bypass signatures, bypassing the delay is a consistent extension of that trust model. The security trade-off is explicit — users who set an executor accept this trust assumption. No code change recommended.

### [L2] No cancellation mechanism for queued transactions [agents: 4]

Once a transaction is queued, there is no way to cancel it. The `queued` mapping entry persists until executed by anyone after the ETA.

**Assessment:** A `cancelQueued` function gated by `onlySelf` would itself go through `execute()`, which is subject to the same timelock delay. By the time the cancellation transaction clears the delay, the original transaction is already past its ETA and executable. This makes a cancel function ineffective without deeper architectural changes (e.g., an executor-only cancel path). Accepted as a known limitation of the timelock design.

### [L3] Unsafe uint16 downcast of threshold [agents: 5]

`init()` (line 40) and `setThreshold()` (line 201) cast `_threshold` from `uint256` to `uint16` without overflow checking. Values above 65535 silently truncate.

**Assessment:** Exploiting this requires 65,536+ owners. The gas cost of the `init()` loop writing that many storage slots is in the billions — no chain supports this in a single transaction. Practically unreachable. The code is technically imprecise but not a real vulnerability.

### [L4] Executor can burn nonces to invalidate owner signatures [agents: 3]

The executor can call `execute()` repeatedly with empty signatures, each call incrementing the nonce and invalidating any pre-signed owner transactions.

**Assessment:** The executor is already trusted with unrestricted execution authority. Nonce burning is a subset of that trust. If the executor is compromised, nonce griefing is the least of concerns — they can drain the wallet directly.

### [L5] Uninitialized implementation contract [agents: 2]

The implementation contract deployed by `MultisigFactory` (line 226) is never initialized. In theory, someone could call `init()` on it if they could satisfy `msg.sender == factory`. Post-Dencun, `selfdestruct` is disabled, so the risk is minimal. The implementation holds no funds by design.

### [L6] `batch()` missing array length validation [agents: 2]

`batch()` (line 157) does not validate that `targets`, `values`, and `datas` arrays have equal lengths. Solidity's ABI decoder will revert on out-of-bounds access, so this is a UX issue (unhelpful error message) rather than a security issue.

### [L7] `removeOwner` breaks sorted-order invariant [agents: 4]

`removeOwner()` uses swap-and-pop (line 182), breaking the sorted order established by `init()`. This does not affect on-chain security — signature verification uses the `isOwner` mapping, not array order — but `getOwners()` returns unsorted results which may affect off-chain tooling.

### [L8] `msg.value` not earmarked when transaction is queued [agents: 1]

When `execute()` is called with `msg.value > 0` and `delay > 0`, the ETH is absorbed into the contract's general balance while the transaction is only queued. The queued transaction will use the contract's balance at execution time, not earmarked funds. This is a design tradeoff — the multisig is expected to hold ETH.

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

Results were deduplicated by `group_key`, gate-evaluated per the Pashov judging framework (4 sequential gates: refutation, reachability, trigger, impact), and reviewed manually to assess practical feasibility.

---

## Disclaimer

This report was generated using an AI-powered parallelized audit framework. AI-assisted audits are a preliminary check and should not be considered a substitute for a formal manual security review by experienced auditors. Always conduct thorough testing, formal verification, and professional audits before deploying smart contracts to mainnet.
