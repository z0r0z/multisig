# Multisig Modules Security Audit Report

**Date:** 2026-04-03
**Target:** `src/mods/` (AllowlistGuard, CancelTx, DeadmanSwitch, SocialRecovery, SpendingAllowance)
**Method:** Pashov Skills — 8-agent parallelized security audit (two passes)
**Solidity:** ^0.8.34

---

## Scope

| Contract | Lines | Description |
|---|---|---|
| `AllowlistGuard` | 30 | Pre-guard that allowlists (target, selector) pairs. Singleton keyed by msg.sender. |
| `CancelTx` | 90 | Executor module: threshold-vote cancel + unanimous forward with nonce. |
| `DeadmanSwitch` | 48 | Post-guard + executor: beneficiary sweeps ETH after inactivity timeout. |
| `SocialRecovery` | 66 | Executor module: guardian proposes, delay, finalize arbitrary calls. |
| `SpendingAllowance` | 50 | Executor module: periodic ETH allowance for a spender address. |

---

## Summary

| # | Severity | Title | Confidence | Agents | Status |
|---|----------|-------|------------|--------|--------|
| 1 | Medium | `DeadmanSwitch.claim` — unchecked overflow bypasses timeout | 85 | 6 | **Resolved** — removed `unchecked` |
| 2 | Medium | `SocialRecovery` — zero delay enables atomic guardian takeover | 80 | 4 | Acknowledged — design choice (instant recovery is valid) |
| 3 | Medium | `SpendingAllowance` — period=0 allows unlimited drain | 80 | 4 | Acknowledged — design choice (per-tx limit is valid) |
| 4 | Medium | `CancelTx.forward` — stuck votes with no reset mechanism | 75 | 3 | **Resolved** — added `bumpForwardNonce()` |
| 5 | Low | `DeadmanSwitch.claim` — heartbeat resets on zero-ETH claim | 70 | 3 | **Resolved** — added `require(amount != 0)` |
| 6 | Low | `SocialRecovery` — single guardian can grief by cancelling proposals | 65 | 3 | Acknowledged — guardians are trusted roles |
| 7 | Low | `DeadmanSwitch` — only sweeps ETH, no token recovery | — | 3 | Acknowledged — scope decision |
| L1 | Lead | `CancelTx.cancel` — stale votes persist across owner re-addition | — | 3 |
| L2 | Lead | `AllowlistGuard` — `bytes4(0)` selector collision (ETH vs short calldata) | — | 2 |
| L3 | Lead | `SpendingAllowance` — uint32 `lastReset` truncation (year 2106) | — | 2 |
| L4 | Lead | `SocialRecovery.finalize` is permissionless — MEV on recovery | — | 2 |
| L5 | Lead | `DeadmanSwitch` — non-vanity deployment creates silent half-functional state | — | 1 |
| L6 | Lead | `SocialRecovery` — guardian can overwrite expired unfinalized proposals | — | 3 |
| L7 | Lead | `CancelTx.cancel` — threshold reduction retroactively activates accumulated votes | — | 2 |
| L8 | Lead | `DeadmanSwitch` — `_timeout = 0` allows instant claim (boundary degeneration) | — | 2 |
| L9 | Lead | `CancelTx.forward` — stale votes survive `forwardEnabled` toggle without nonce bump | — | 2 |

---

## Findings

### [F-1] MEDIUM — `DeadmanSwitch.claim` unchecked overflow bypasses timeout [agents: 6]

**Contract:** DeadmanSwitch
**Function:** `claim()` (line 42–43)
**Bug class:** unchecked-overflow
**Group key:** DeadmanSwitch | claim | unchecked-overflow

**Description:** `claim()` checks `block.timestamp >= c.lastActivity + c.timeout` inside an `unchecked` block. If `timeout` is set to `type(uint256).max` (intending "never claimable"), the addition wraps: for any `lastActivity > 0`, `lastActivity + type(uint256).max` overflows to `lastActivity - 1`, which is always less than `block.timestamp`. The beneficiary can claim immediately.

**Attack path:**
1. Multisig calls `configure(beneficiary, type(uint256).max)` intending "permanent lock".
2. `lastActivity = block.timestamp` (e.g., 1700000000).
3. Beneficiary calls `claim()`: `1700000000 + type(uint256).max` wraps to `1699999999`.
4. `block.timestamp >= 1699999999` passes. Wallet drained.

**Gate evaluation:**
- Gate 1: No refutation — the overflow is mathematically certain. CLEARS.
- Gate 2: Requires multisig to set a very large timeout. Setting max-uint intending "infinite" is a realistic misconfiguration (-10). CLEARS.
- Gate 3: Beneficiary is semi-trusted but external. CLEARS.
- Gate 4: Full ETH drain. Material. CONFIRMED.

**Confidence:** 85

**Fix:** Remove `unchecked` from the timeout check, or add `require(_timeout <= type(uint128).max)` in `configure()`.

**Resolution:** Removed `unchecked` block from the `lastActivity + timeout` check. Checked arithmetic now reverts on overflow, making `type(uint256).max` timeout behave as expected (never claimable).

---

### [F-2] MEDIUM — `SocialRecovery` zero delay enables atomic guardian takeover [agents: 4]

**Contract:** SocialRecovery
**Function:** `propose()` + `finalize()` (lines 37–58)
**Bug class:** boundary-degeneration
**Group key:** SocialRecovery | propose | boundary-degeneration

**Description:** `delay` defaults to 0 if `setDelay()` is never called. With `delay == 0`, `eta = block.timestamp + 0`, and `finalize()` passes immediately (`block.timestamp >= eta`). A guardian can atomically propose and finalize via a helper contract in a single transaction, executing arbitrary calls with no owner reaction window.

**Attack path:**
1. Multisig configures SocialRecovery as executor but forgets to call `setDelay()`.
2. Guardian deploys attack contract: `propose(multisig, attacker, balance, "")` → `finalize(multisig, attacker, balance, "")`.
3. Both pass in same tx. Wallet drained.

**Gate evaluation:**
- Gate 1: Owners could set delay > 0, but default is 0. Speculative. CLEARS.
- Gate 2: Forgetting `setDelay` or misconfiguring to 0 is realistic (-10). CLEARS.
- Gate 3: Any guardian can trigger. CLEARS.
- Gate 4: Full wallet drain. CONFIRMED.

**Confidence:** 80

**Fix:** Enforce minimum delay in `propose()`: `require(delay[multisig] > 0, NotReady())`.

---

### [F-3] MEDIUM — `SpendingAllowance` period=0 allows unlimited drain [agents: 4]

**Contract:** SpendingAllowance
**Function:** `spend()` (lines 34–49)
**Bug class:** boundary-degeneration
**Group key:** SpendingAllowance | spend | boundary-degeneration

**Description:** When `period == 0`, the condition `block.timestamp >= uint256(c.lastReset) + c.period` is always true, resetting `spent = 0` on every call. The spender can call `spend(multisig, attacker, allowance)` repeatedly, draining up to `allowance` per call with no cumulative limit.

**Gate evaluation:**
- Gate 1: Owners could set period > 0. No validation prevents 0. CLEARS.
- Gate 2: Misconfiguring period=0 is achievable (-10). CLEARS.
- Gate 3: Spender (semi-trusted) triggers. CLEARS.
- Gate 4: Full wallet drain over multiple calls. CONFIRMED.

**Confidence:** 80

**Fix:** Add `require(_period > 0)` in `configure()`.

---

### [F-4] MEDIUM — `CancelTx.forward` stuck votes with no reset mechanism [agents: 3]

**Contract:** CancelTx
**Function:** `forward()` (lines 69–89)
**Bug class:** desynchronized-coupling
**Group key:** CancelTx | forward | desynchronized-coupling

**Description:** `forward()` requires unanimity among all current owners. The `forwardNonce` is included in the vote `id` and increments only on successful execution (line 85). If a forward vote accumulates but never completes (e.g., owner removed mid-vote), the `id` is permanently polluted. A new forward with identical `(target, value, data)` produces the same stuck `id` because the nonce hasn't changed. There is no mechanism to bump the nonce or clear votes without completing execution.

**Attack path:**
1. 3-owner multisig [A, B, C]. A and B vote on forward for `id = hash(target, value, data, nonce=0)`.
2. C is removed, D is added.
3. Forward stuck — D hasn't voted, nonce=0 unchanged.
4. New forward attempt with same params → same `id` (nonce still 0) → A and B already voted, D hasn't. D votes → executes. **But**: if A was also changed, votes are permanently stuck with no reset.

**Gate evaluation:**
- Gate 1: Owner changes during active forward vote. No reset exists. CLEARS.
- Gate 2: Owner rotation during forward voting is realistic for timelocked multisigs (-10). CLEARS.
- Gate 3: Normal multisig operations trigger this. CLEARS.
- Gate 4: Permanent DoS of forward for that parameter set. Material for timelock bypass mechanism. CONFIRMED.

**Confidence:** 75

**Fix:** Add a `bumpForwardNonce()` function callable by the multisig, or include an owner-set hash in the vote `id`.

**Resolution:** Added `bumpForwardNonce()` — callable by the multisig (msg.sender keying) to invalidate stuck forward votes by advancing the nonce. New forward proposals for the same params get a fresh `id`.

---

### [F-5] LOW — `DeadmanSwitch.claim` heartbeat resets on zero-ETH claim [agents: 3]

**Contract:** DeadmanSwitch
**Function:** `claim()` (lines 39–47)
**Bug class:** temporal-inconsistency
**Group key:** DeadmanSwitch | claim | temporal-inconsistency

**Description:** `claim()` calls `IMultisig(multisig).execute()`, which triggers the post-guard (`DeadmanSwitch.execute()`), resetting `lastActivity = block.timestamp`. If `multisig.balance == 0` (wallet holds only tokens), the "transfer" sends 0 ETH but the heartbeat resets. The beneficiary must wait another full timeout. A griefer could also send 1 wei to the multisig between claims, forcing repeated timeout waits for dust cost.

**Confidence:** 70

**Resolution:** Added `require(amount != 0, StillAlive())` after reading `multisig.balance`. Claims on empty wallets now revert, preventing the heartbeat reset without a meaningful transfer.

---

### [F-6] LOW — `SocialRecovery` single guardian can grief cancellations [agents: 3]

**Contract:** SocialRecovery
**Function:** `cancel()` (lines 60–65)
**Bug class:** griefing
**Group key:** SocialRecovery | cancel | griefing

**Description:** Any single guardian can unilaterally cancel pending proposals. In multi-guardian setups, one rogue guardian can perpetually cancel legitimate recovery proposals, creating an indefinite DoS on the recovery mechanism. No quorum is required for cancellation, creating asymmetry with the proposal mechanism.

**Confidence:** 65

---

### [F-7] LOW — `DeadmanSwitch` only sweeps ETH [agents: 3]

**Contract:** DeadmanSwitch
**Function:** `claim()` (line 45)
**Bug class:** incomplete-coverage
**Group key:** DeadmanSwitch | claim | incomplete-coverage

**Description:** `claim()` transfers only `multisig.balance` (native ETH). ERC20 tokens, ERC721 NFTs, and ERC1155 assets are not recoverable. Significant value can be stranded in the multisig after the beneficiary claims.

---

## Leads

_High-signal trails for manual review. Not scored._

- **[L1] CancelTx.cancel — stale cancel votes after owner re-addition** — If owner A votes, is removed, then re-added, their `cancelVoted` entry persists and is counted without A consciously re-voting. Cleanup only deletes current owners' entries. Low impact since cancel is a safety mechanism, not a value-extraction path.

- **[L2] AllowlistGuard `bytes4(0)` selector collision** — When `data.length < 4`, selector defaults to `bytes4(0)`. Allowlisting `bytes4(0)` permits ETH transfers AND calls with 1–3 bytes data. The NatSpec documents the ETH transfer case; short-calldata is an edge case.

- **[L3] SpendingAllowance uint32 `lastReset` truncation** — `lastReset = uint32(block.timestamp)` silently wraps after 2106. Post-overflow, period reset fires every call, collapsing the rate limit. ~80-year horizon.

- **[L4] SocialRecovery.finalize is permissionless** — Anyone can call `finalize()` once ETA passes. MEV bots can front-run or force execution. Mitigation: guardians can `cancel()` before ETA. Impact is typically timing only.

- **[L5] DeadmanSwitch non-vanity deployment** — `execute()` (post-guard) works at any address, but `configure()` requires `uint160(address(this)) & 0xFFFF == 0x1111`. Deploying at a non-vanity address creates a heartbeat recorder with no beneficiary configuration possible. No warning.

- **[L6] SocialRecovery proposal overwrite** — After a proposal's ETA passes, any guardian can call `propose()` to overwrite the unfinalized proposal. A malicious guardian can front-run `finalize()` with a new `propose()`, replacing the pending hash and resetting the delay.

- **[L7] CancelTx.cancel — threshold reduction retroactively activates accumulated cancel votes** — `cancel()` reads the live `threshold()` at the moment the final vote lands. If cancel votes accumulate below the current threshold and the threshold is subsequently lowered (via a separate multisig execution), a subsequent `cancel()` call can cross the new lower threshold with the same vote count. Example: 5-of-5 multisig, owners A/B/C vote cancel (count=3, threshold=5, no cancel). Owners lower threshold to 3. Owner D calls cancel → count=4 >= 3 → cancel fires. The threshold reduction retroactively enables the pending cancel. **Assessment:** Lowering threshold requires threshold-of-owners to agree. The cancel mechanism is a safety feature. Cross-operation interference is a design consideration, not an exploit.

- **[L8] DeadmanSwitch `_timeout = 0` allows instant claim** — `configure()` accepts `_timeout = 0`. The check `block.timestamp >= c.lastActivity + 0` is always true, so the beneficiary can claim immediately after any heartbeat — including the one triggered by `configure()` itself. This is the same boundary-degeneration pattern as F-2 (SocialRecovery zero delay) and F-3 (SpendingAllowance period=0). **Assessment:** Acknowledged as a design choice — same reasoning. `_timeout = 0` means "no deadman switch protection." Owners who configure zero timeout accept this.

- **[L9] CancelTx.forward — stale votes survive `forwardEnabled` toggle without nonce bump** — When `forwardEnabled` is toggled to `false`, existing `forwardVoted` entries persist. If `forwardEnabled` is later re-enabled without calling `bumpForwardNonce()`, old votes apply to the same `id` under the unchanged nonce. A vote cast before the toggle counts toward unanimity after the toggle. **Assessment:** Partially mitigated by `bumpForwardNonce()`. No automatic nonce bump on disable. Multisigs should call `bumpForwardNonce()` when disabling forward to invalidate pending votes. Operational consideration.

---

## Changes Made

| Change | File | Finding | Description |
|--------|------|---------|-------------|
| Remove `unchecked` from timeout check | `DeadmanSwitch.sol:42-43` | F-1 | Checked arithmetic prevents overflow on large timeout values |
| Add `require(amount != 0)` | `DeadmanSwitch.sol:44` | F-5 | Prevents zero-ETH claims from resetting heartbeat |
| Add `bumpForwardNonce()` | `CancelTx.sol:30-34` | F-4 | Multisig can invalidate stuck forward votes by advancing nonce |

---

## Methodology

8-agent parallelized audit following the [Pashov Skills](https://github.com/pashov/skills) framework:

1. **Vector Scan** — Reentrancy, replay, front-running, griefing, DoS
2. **Math Precision** — Overflow, precision loss, unsafe downcasts, zero-value edge cases
3. **Access Control** — Permission gaps, initialization, privilege escalation, confused deputy
4. **Economic Security** — Value extraction, griefing economics, broken incentives, MEV
5. **Execution Trace** — Parameter divergence, stale reads, encoding mismatches
6. **Invariant** — State couplings, conservation laws, boundary conditions
7. **Periphery** — Infrastructure, gas complexity, deployment constraints
8. **First Principles** — Implicit assumptions, temporal inconsistencies, boundary degeneration

Results deduplicated by `group_key`, gate-evaluated per the Pashov judging framework (4 sequential gates: refutation, reachability, trigger, impact).

### Agent Finding Source Map

| Finding | Agents that flagged |
|---|---|
| F-1 (unchecked overflow) | 1, 2, 3, 6, 7, 8 |
| F-2 (zero delay) | 1, 3, 4, 8 |
| F-3 (period=0) | 2, 4, 6, 8 |
| F-4 (stuck forward) | 1, 5, 8 |
| F-5 (heartbeat reset) | 4, 5, 6 |
| F-6 (cancel grief) | 3, 4, 6 |
| F-7 (ETH only) | 4, 5, 7 |

### Rejected Findings

| Agent | Claim | Rejection reason |
|---|---|---|
| 1 | SpendingAllowance reentrancy via period-reset | Period reset fires at top of `spend()` before external call. Re-entrant call sees `lastReset = block.timestamp`, same block means `block.timestamp >= lastReset + period` only if period=0 (covered by F-3). For period > 0, no re-entrancy benefit. |
| 1 | DeadmanSwitch.claim reentrancy | Config state (`lastActivity`, `timeout`) is not modified by `claim()` directly — the post-guard modifies `lastActivity`. Re-entering `claim()` would read the updated `lastActivity` (reset to `block.timestamp`), failing the `StillAlive` check. Not exploitable. |
| 1 | SocialRecovery.finalize re-entrancy via guardian propose | `pending` and `eta` are deleted before `execute()`. A re-entrant `propose()` by a guardian sets new state but doesn't affect the current finalization. Not an exploit — just a new proposal. |

### Second Pass (2026-04-03)

Fresh 3-agent Opus/Sonnet parallelized re-audit (Vector Scan focus). Confirmed all existing findings. Surfaced three new leads: L7 (CancelTx threshold reduction retroactively activates cancel votes), L8 (DeadmanSwitch zero-timeout instant claim), L9 (stale forward votes survive forwardEnabled toggle).

**Rejected findings from second pass:**

| Agent | Claim | Rejection reason |
|---|---|---|
| Vector | DeadmanSwitch post-guard resets heartbeat on claim (rated Critical) | Correct behavior — after a full-balance sweep, the heartbeat reset means the beneficiary must wait another full timeout if the wallet later receives more ETH. `require(amount != 0)` prevents zero-balance reentrancy. Not exploitable. |
| Vector | Owner set manipulation blocks forward via addOwner front-run (rated High) | Forward requires unanimity of *current* owners by design. If the owner set changes, new owners must also vote. Requires threshold-of-owners to add the new owner, who could also just `bumpForwardNonce()`. Not a bug. |
| Vector | SpendingAllowance double-spend via reentrancy (rated High, self-dismissed) | CEI is correctly followed (`c.spent += amount` before external call). EVM revert propagation ensures failed sub-calls roll back all state. Agent correctly dismissed its own finding. |
| Vector | Non-vanity module at 0x1111 address breaks post-guard (rated Medium) | Extremely unlikely coincidental address. Modules that don't implement `execute()` should not be deployed at vanity addresses. Informational. |

---

## Disclaimer

This report was generated using an AI-powered parallelized audit framework. AI-assisted audits are a preliminary check and should not be considered a substitute for a formal manual security review by experienced auditors. Always conduct thorough testing, formal verification, and professional audits before deploying smart contracts to mainnet.
