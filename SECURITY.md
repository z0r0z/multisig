# Security

> **Purpose:** Security posture document for `src/Multisig.sol`. Summarizes prior audit findings with developer responses, documents defense mechanisms and invariants, and provides structured guidance for future reviewers to avoid duplicate findings and produce consistent reports.

## Prior Audit

**Date:** 2026-04-03
**Method:** Pashov Skills — 8-agent parallelized security audit (two passes)
**Full report:** [`audit/report.md`](audit/report.md)

---

## Architecture Overview

| Component | Lines | Description |
|---|---|---|
| `Multisig` | 1–245 | Threshold multisig with optional timelock, executor role, and pre/post guardian hooks. All mutable state (`delay`, `nonce`, `threshold`, `ownerCount`, `executor`) packed in a single storage slot. |
| `MultisigFactory` | 247–281 | Minimal proxy (PUSH0 clone) factory with CREATE2 and Solady-style sender-bound salt. |

### Access Control Model

There are **no admin keys**. The factory is permissionless. The `implementation` is deployed in the constructor and is immutable.

- **`onlySelf`** — `msg.sender == address(this)`. All configuration changes (`addOwner`, `removeOwner`, `setThreshold`, `setDelay`, `setExecutor`, `batch`, `delegateCall`) require the multisig to call itself via a signed `execute`.
- **Executor** — Optional trusted address that bypasses signatures and timelock. Comparable to Safe modules. This is critical context: any finding that requires "the executor does X" is a trust assumption, not a vulnerability.
- **Owners** — Must collectively produce >= threshold valid signatures. Individual owners below threshold have no unilateral power.

### Key Design Decisions

- **Executor is fully trusted.** It bypasses signatures and timelock by design. If the executor is compromised, it has unilateral control. This is the intended trust model.
- **Guardian hooks are encoded via executor vanity address.** Leading `0x1111` = pre-hook, trailing `0x1111` = post-hook. No storage overhead.
- **Pre-hook fires before signature validation.** Intentional — allows blocklist/policy checks before authorization.
- **Owner linked list is sorted on init but not on addOwner.** Signature verification checks ascending signer order independently of list order.
- **CREATE2 salt uses Solady `checkStartsWith` pattern.** Zero-prefix = open deploy, sender-prefix = sender-bound. No on-chain hashing of init params (unlike Safe).

---

## Defense Mechanisms

Before flagging a finding, verify it is not already neutralized by one of these:

| Defense | Mechanism | What It Prevents |
|---------|-----------|-----------------|
| **Ascending signer order** | `signer > prev` check in ecrecover loop (lines 123, 99) | Duplicate signers, signature replay within a single call |
| **EIP-712 domain separation** | `DOMAIN_SEPARATOR()` includes `address(this)` and `chainId` | Cross-chain replay, cross-wallet replay |
| **Nonce increment** | `nonce++` in unchecked block, included in EIP-712 hash | Transaction replay |
| **Sender-bound salt** | `salt >> 96 == uint160(msg.sender)` (line 266) | CREATE2 front-running for pre-funded addresses |
| **Init guard** | `threshold == 0` check (line 40) — init only succeeds once | Double initialization |
| **Factory-only init** | `msg.sender == factory \|\| msg.sender == address(this)` (line 38) | Third-party initialization of implementation or clones |
| **onlySelf modifier** | `msg.sender == address(this)` on all config functions | Unauthorized state changes |
| **Queued hash deletion** | `delete queued[hash]` before external call (line 153) | Replay of queued transactions |
| **cancelQueued** | Executor-only (line 145), no timelock | Emergency cancellation within delay window |
| **Solady-style assembly clone** | PUSH0 minimal proxy (lines 267–277) | Deployment gas overhead, non-deterministic addresses |

---

## Key Invariants

These properties should hold. If you find a violation, it's likely a real finding:

1. **Init is one-shot** — `threshold` starts at 0 and is set to a nonzero value in `init()`. Once nonzero, `init()` reverts. No path resets `threshold` to 0.
2. **Owner linked list is well-formed** — `SENTINEL → owner₁ → owner₂ → ... → ownerₙ → SENTINEL`. No cycles, no dangling pointers, `ownerCount` matches actual list length.
3. **Nonce is monotonically increasing** — `nonce++` in unchecked block. Each `execute` consumes exactly one nonce. No path decrements or resets the nonce.
4. **Queued hash is a one-shot latch** — `queued[hash]` is set once (in `execute` with delay), deleted on `executeQueued` or `cancelQueued`, and never re-set for the same hash (nonce prevents collision).
5. **Signature threshold is enforced for non-executor callers** — `sigs.length == threshold * 65` and each signer is a valid owner in ascending order.
6. **Clone delegates to immutable implementation** — The factory's `implementation` is set once in the constructor and is immutable. All clones delegate to this address.
7. **Single storage slot packing** — `delay` (uint32) + `nonce` (uint32) + `threshold` (uint16) + `ownerCount` (uint16) + `executor` (address) fit in one 256-bit slot. No field write corrupts another.

---

## Resolved Findings

| ID | Title | Resolution |
|---|---|---|
| F-3 | Queued transactions had no cancellation mechanism | Added `cancelQueued(bytes32)` — executor-only emergency cancellation. The executor is the only role that can act within the timelock window without delay. |

---

## Acknowledged Findings (Design Tradeoffs)

### F-1: Pre-fund theft via zero-prefix CREATE2 salt front-running

**Severity:** Medium | **Confidence:** 75

The factory allows zero-prefix salts (`salt >> 96 == 0`) for permissionless deploys. Since the proxy init code is identical regardless of owners, an attacker can front-run a zero-prefix deploy with different owners and claim the address. If ETH was pre-funded to that address, the attacker controls it.

**Response:** This is the canonical Solady `LibClone.checkStartsWith` pattern. Zero-prefix salts are for gas-efficient relayer deploys where no pre-funding occurs. Sender-bound salts (`salt >> 96 == uint160(msg.sender)`) prevent front-running for the pre-fund case. Both Safe and this factory allow open deploys — this factory just does it without hashing initializer params into the salt, saving ~160 gas.

**Guidance for reviewers:** This is a known tradeoff, not a bug. Do not re-file unless you find a scenario where sender-bound salts fail to protect pre-funded addresses.

### F-2: Pre-execution hook fires before signature validation

**Severity:** Medium | **Confidence:** 90

When the executor address has leading bytes `0x1111`, the pre-hook external call fires before signature verification. Unvalidated parameters are forwarded to the executor contract.

**Response:** Intentional. The guardian needs to see (and potentially block) transactions before authorization — this is a blocklist/policy-enforcement pattern. EVM atomicity ensures no state persists if the subsequent sig check fails (for non-executor callers). When `msg.sender == executor`, sigs are already bypassed by design.

### F-4: `executeQueued` callable by anyone

**Severity:** Low | **Confidence:** 65

Once a queued transaction's ETA passes, any address can trigger execution.

**Response:** Intentional for relayer compatibility. `cancelQueued` (executor-only) provides the emergency brake.

### F-5: Post-hook fires even when transaction is only queued

**Severity:** Low | **Confidence:** 75

The post-hook fires unconditionally — including when a transaction is queued rather than executed.

**Response:** Intentional. The guardian can inspect queued parameters and revert the entire transaction (including the queue write) to act as a veto on queuing.

### F-6: Both pre-hook and post-hook fire for crafted executor address

**Severity:** Low | **Confidence:** 75

An executor address matching both `0x1111...` prefix and `...0x1111` suffix triggers `executor.execute()` twice per transaction.

**Response:** Intentional dual-hook design. Pre-hook is for blocking/banning, post-hook is for notification/veto.

---

## Leads (Reviewed, Not Scored)

These were investigated during the audit and determined to be non-issues or accepted risks. **Do not re-file** unless you have a concrete exploit path not covered below.

| ID | Lead | Assessment |
|---|---|---|
| L1 | Executor bypasses sigs + timelock | By design — trusted module pattern |
| L2 | Executor can burn nonces to invalidate owner sigs | Subset of executor trust — if compromised, nonce griefing is the least concern |
| L3 | Unsafe uint16 downcast of threshold | Unreachable — 65,536+ owners exceeds block gas limit |
| L4 | No low-s check in ecrecover (signature malleability) | Mitigated by sorted-signer ordering; both `(s)` and `(n-s)` recover the same address, and ascending signer check prevents double-counting |
| L5 | uint32 nonce overflow in unchecked block | ~4B txs required — impractical |
| L6 | Stale executor reference in post-hook | Cached at function entry; if `setExecutor` is called mid-tx, post-hook uses old address. Atomic tx limits impact |
| L7 | No reentrancy guard on execute | Non-executor reentrant calls still require valid sigs per nonce |
| L8 | Uninitialized implementation contract | `init()` requires `msg.sender == factory`; holds no funds |
| L9 | `batch()` missing array length validation | Solidity ABI decoder reverts on out-of-bounds |
| L10 | `addOwner` breaks sorted-order invariant | Cosmetic — sig verification checks signer order, not list order |
| L11 | `msg.value` not earmarked when tx is queued | Design tradeoff — multisig is expected to hold ETH |

---

## False Positive Patterns (Do NOT Flag These)

These patterns were repeatedly surfaced by automated auditors and confirmed as non-issues. If your analysis produces one of these, discard it:

| Pattern | Why It's Not a Bug |
|---------|-------------------|
| "Executor can steal all funds" | The executor is an intentionally trusted role — this is the design, not a finding. Users who set an executor accept full trust. Comparable to Safe modules. |
| "Pre-hook fires before sig validation" | Intentional guardian pattern (F-2). EVM atomicity prevents state persistence for unauthorized callers. |
| "No reentrancy guard on execute" | Each reentrant call requires valid signatures for a fresh nonce (L7). The nonce increment is the reentrancy defense. |
| "Anyone can call executeQueued" | Intentional for relayer compatibility (F-4). cancelQueued is the emergency brake. |
| "addOwner doesn't enforce sorted order" | Cosmetic (L10). Sig verification checks ascending *signer* order in the signature array, not the linked list order. |
| "uint32 nonce will overflow" | Requires ~4B transactions (L5). Impractical on any chain. |
| "Implementation contract is uninitialized" | `init()` requires `msg.sender == factory` (L8). Third parties cannot initialize it. It holds no funds. |
| "msg.value is not earmarked for queued tx" | Design tradeoff (L11). The multisig is expected to hold ETH. Queued txs use whatever balance exists at execution time. |
| "Zero-prefix salt allows front-running" | Known tradeoff (F-1). Use sender-bound salt for pre-fund. Zero-prefix is for open/relayer deploys. |
| "delegateCall can corrupt storage" | Intentional power — gated by `onlySelf`. Requires threshold-of-n signatures. Same design as Safe. |
| "Force-fed ETH via selfdestruct" | Economically irrational — attacker donates their own ETH. No accounting invariant depends on `address(this).balance`. |
| "No admin can freeze/pause" | There is no admin. `onlySelf` = self-governance. This is the design. |

---

## Trust Assumptions

1. **Executor** — Has unilateral, immediate control over the wallet. Setting an executor is equivalent to granting a master key. Owners should only set an executor they fully trust (e.g., a security council multisig or social recovery guardian).
2. **Owners** — Must collectively control >= threshold keys. Individual owners below threshold have no unilateral power.
3. **Factory deployer** — The factory is permissionless. The `implementation` is deployed in the constructor and is immutable. No admin keys.
4. **Timelock** — Protects against owner compromise by giving stakeholders an exit window. The executor operates outside the timelock by design.
5. **Guardian (executor with vanity address)** — Trusted to act honestly in pre/post hooks. A malicious guardian can block all transactions (pre-hook revert) or observe transaction parameters before execution.

---

## Guidance for Future Reviewers

### Scope

- `src/Multisig.sol` — single file, ~280 lines, contains both `Multisig` and `MultisigFactory`
- Test suite: `test/Multisig.t.sol`, `test/EIP7702.t.sol`, `test/Gas.t.sol`
- No external dependencies beyond forge-std

### How to Run

```bash
forge build
forge test -vvv
forge test --mc GasTest -vv   # gas benchmarks
forge snapshot                 # gas snapshot
```

### Audit Methodology

Work in **three rounds**, producing output for each before moving to the next.

#### Round 1: Systematic Code Review

Walk through each vulnerability category in order. For each, cite specific lines, trace the code path, and state your conclusion. Include categories where you find nothing — say "No issues found" with a one-sentence explanation of the defense mechanism. Cover every function with external visibility.

**Vulnerability categories:**

1. **Reentrancy** — No `nonReentrant` guard. Defense is nonce-per-call. Verify that every reentrant path requires a fresh nonce and valid signatures. Check guardian hook callbacks.
2. **Signature / Replay** — EIP-712, ecrecover loop, ascending signer order, nonce. Check for cross-chain replay, cross-wallet replay, malleability, `ecrecover` returning `address(0)`.
3. **Access Control** — `onlySelf`, executor bypass, factory-only init. Check for privilege escalation paths, especially via `delegateCall` and `batch`.
4. **Front-Running** — CREATE2 salt pattern, `executeQueued` timing, guardian hook parameter exposure.
5. **Timelock Logic** — Queue/execute/cancel state machine. Check for hash collisions, replay after cancellation, timing edge cases, nonce reuse.
6. **Arithmetic** — uint16 downcasts, uint32 nonce in unchecked, signature length math. Check for overflow/underflow paths.
7. **Storage Packing** — Single-slot layout. Verify reads/writes don't corrupt adjacent fields.
8. **Linked List Integrity** — Owner add/remove, sentinel handling. Check for cycles, dangling pointers, off-by-one in ownerCount.
9. **EIP-7702** — Dual-path init (factory vs self-call). Verify EOA superuser semantics don't bypass intended restrictions.
10. **External Calls** — `target.call{value}(data)` in execute/executeQueued/batch, `delegatecall` in delegateCall, guardian hooks. Check return value handling.

#### Round 2: Cross-Function Analysis

Look for **interactions between mechanisms** — places where two individually-safe features create a vulnerability when combined. Focus on:
- Guardian hooks + reentrancy via `execute`
- Executor bypass + timelock + nonce burning
- `delegateCall` + `onlySelf` + storage layout
- `batch` + `addOwner`/`removeOwner` + threshold changes
- EIP-7702 EOA key + multisig init + executor

For each candidate attack, estimate the economic cost vs gain.

#### Round 3: Adversarial Validation

Switch roles. You are now a **budget-protecting skeptic** whose job is to minimize false positives. For every finding from Rounds 1 and 2:

1. **Attempt to disprove it.** Find the code path, guard, or constraint that prevents the attack.
2. **Check it against the Known Findings.** If it matches F-1 through F-6 or L1 through L11, discard it as a duplicate.
3. **Check it against the False Positive Patterns table.** If it matches, discard it.
4. **Apply the trust-assumption rule.** If it requires a compromised executor, it is not a vulnerability — it is within the executor's trust boundary.
5. **Rate your confidence** (0-100) in the finding surviving disproof.
6. **Only include findings that survive all five checks.**

### Critical Code Paths (Priority Order)

1. **`execute`** (lines 106–141) — Signature verification, executor bypass, timelock branching, guardian hooks. Highest-risk function.
2. **`executeQueued`** (lines 149–157) — Permissionless execution of timelocked transactions. Hash-based replay prevention.
3. **`init`** (lines 37–56) — Owner linked list construction, threshold/delay/executor setup. One-shot guard.
4. **`isValidSignature`** (lines 84–103) — ERC-1271 support. Separate EIP-712 domain from `execute`.
5. **`delegateCall`** (lines 181–183) — Arbitrary code execution in wallet context. Storage corruption risk.
6. **`create`** (lines 260–280) — Factory clone deployment. Assembly CREATE2 + init call.

### Severity Criteria

| Severity | Definition |
|----------|------------|
| **Critical** | Direct theft of funds OR permanent freeze of wallet. Exploitable by any external account without owner signatures. |
| **High** | Temporary freeze of funds, bypass of signature/timelock for non-executor callers, or significant economic damage. |
| **Medium** | Griefing, DoS, or economic inefficiency with real impact. Attacker gains no direct profit. |
| **Low** | Edge case, configuration-dependent, or requires unlikely conditions. |
| **Informational** | Best practice deviation or theoretical concern with no practical exploit path. |

**Severity adjustment rules** (apply in order):

1. **Trust-assumption rule:** If the finding requires a compromised executor — downgrade by 2 levels or mark Out of Scope. A trusted executor acting maliciously is a trust assumption, not a vulnerability.
2. **Economic irrationality:** If attack cost > gain, downgrade by 1 level.
3. **User-controlled mitigation:** If the user can avoid the issue through their own action (e.g., using sender-bound salt), downgrade by 1 level.

### Report Format

For each finding, use this structure:

```
### [SEVERITY-NUMBER] Title

**Severity:** Critical / High / Medium / Low / Informational
**Confidence:** 0-100
**Contract:** Multisig / MultisigFactory
**Function:** `functionName`, line(s) N-M
**Bug class:** (e.g., reentrancy, replay, front-running, access-control)

**Description:**
One paragraph. Reference specific variable names and line numbers.

**Attack Path:**
1. Attacker calls `function(args)` — this does X
2. State change: Y happens because Z
3. Result: quantified impact

**Proof of Concept:** (required for Medium+)
Concrete call sequence with actual function signatures and parameter values.

**Disproof Attempt:**
How you tried to disprove this finding. What defenses did you check?
Why does the attack survive despite those defenses?

**Gate Evaluation:**
- Gate 1 (Refutation): Can design intent explain this? [Yes/No]
- Gate 2 (Reachability): Is the state reachable? [Yes/No]
- Gate 3 (Trigger): Can an unprivileged attacker trigger it? [Yes/No]
- Gate 4 (Impact): Is the impact material? [Yes/No]
- Duplicates Known Finding? [No / Yes: F-N or L-N]

**Recommendation:**
Specific, minimal fix — one code change, not a redesign.
```

Findings must clear all four gates to be scored. Leads are trails that cleared some but not all gates.

### Invariant Verification

Your report must include a table verifying each invariant from the "Key Invariants" section:

| # | Invariant | Verified / Violated | Evidence |
|---|-----------|---------------------|----------|
| 1 | Init is one-shot | | |
| 2 | Owner linked list is well-formed | | |
| 3 | Nonce is monotonically increasing | | |
| 4 | Queued hash is one-shot | | |
| 5 | Signature threshold enforced for non-executor | | |
| 6 | Clone delegates to immutable implementation | | |
| 7 | Single storage slot packing is correct | | |

### Category Coverage Matrix

Your report must include a conclusion for every vulnerability category:

| # | Category | Result | Defense Verified |
|---|----------|--------|-----------------|
| 1 | Reentrancy | | |
| 2 | Signature / Replay | | |
| 3 | Access Control | | |
| 4 | Front-Running | | |
| 5 | Timelock Logic | | |
| 6 | Arithmetic | | |
| 7 | Storage Packing | | |
| 8 | Linked List Integrity | | |
| 9 | EIP-7702 | | |
| 10 | External Calls | | |
