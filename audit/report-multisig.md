# Multisig Security Audit Report

**Date:** 2026-04-03 (updated)
**Previous:** 2026-04-02
**Target:** `src/Multisig.sol` (Multisig + MultisigFactory)
**Method:** Pashov Skills — 8-agent parallelized security audit (three passes)
**Solidity:** ^0.8.34

---

## Scope

| Contract | Lines | Description |
|---|---|---|
| `Multisig` | 4–265 | Threshold multisig with optional timelock, executor role, pre/post guardian hooks, and onchain approvals |
| `MultisigFactory` | 267–321 | Minimal proxy (PUSH0 clone) factory with CREATE2 and `createWithCalls` |

---

## Summary

| # | Severity | Title | Confidence | Agents | Status |
|---|----------|-------|------------|--------|--------|
| 1 | Medium | Pre-fund theft via zero-prefix CREATE2 salt front-running | 75 | 1 | Acknowledged — design tradeoff (use sender-bound salt for pre-fund) |
| 2 | Medium | Pre-execution hook fires before signature validation | 90 | 7 | Acknowledged — intentional guardian/ban-check pattern |
| 3 | Medium | Queued transactions had no cancellation mechanism | 80 | 7 | **Partially resolved** — `cancelQueued()` added (executor-only); without executor, queued txs remain irrevocable by design |
| 4 | Low | `executeQueued` callable by anyone — no access control | 65 | 7 | Design choice — relayer compatibility |
| 5 | Low | Post-execution hook fires even when transaction is only queued | 75 | 2 | Acknowledged — intentional, allows guardian to veto queuing |
| 6 | Low | Both pre-hook and post-hook fire for crafted executor address | 75 | 5 | Acknowledged — intentional dual-hook design |
| L1 | Lead | Executor bypasses both signatures and timelock | — | 7 | By design — trusted module (Safe-like pattern) |
| L2 | Lead | Executor can burn nonces to invalidate owner signatures | — | 3 | By design — subset of executor trust |
| L3 | Lead | Unsafe uint16 downcast of threshold | — | 5 | Unreachable (65536+ owners infeasible) |
| L4 | Lead | Signature malleability (no low-s check in ecrecover) | — | 2 | Mitigated by sorted-signer ordering |
| L5 | Lead | uint32 nonce overflow in unchecked block | — | 2 | Impractical (~4B txs required) |
| L6 | Lead | Stale executor reference in post-hook | — | 1 | Accepted — atomic tx semantics limit impact |
| L7 | Lead | No reentrancy guard on execute (hook interaction) | — | 1 | Accepted — nonce-per-call is the reentrancy defense |
| L8 | Lead | Uninitialized implementation contract | — | 2 | Unreachable — impossible to initialize (see L8 details) |
| L9 | Lead | `batch()` missing array length validation | — | 2 | Solidity ABI decoder catches |
| L10 | Lead | `addOwner` breaks sorted-order invariant | — | 4 | Cosmetic — off-chain tooling only |
| L11 | Lead | `msg.value` not earmarked when transaction is queued | — | 1 | Design tradeoff |
| L12 | Lead | EIP-7702 EOA key remains a superuser | — | 1 | Inherent 7702 property, not a contract bug |
| L13 | Lead | Fallback silently succeeds for unknown selectors | — | 1 | Not exploitable — requires threshold sigs |
| L14 | Lead | `isValidSignature` type hash differs from Safe | — | 1 | Intentional — own signing domain |
| L15 | Lead | No ERC-1271 inline signature verification | — | 1 | Intentional — contract owners use `approve()` or `msg.sender` bypass instead |
| L16 | Lead | `executeQueued` does not re-validate signer set | — | 1 | Accepted — re-validation requires on-chain sig storage |
| L17 | Lead | Pre/post hook return values silently discarded | — | 1 | Accepted — revert-based enforcement is the intended pattern |
| L18 | Lead | v=0 `msg.sender` bypass asymmetry: `execute` vs `isValidSignature` | — | 3 | Intentional — submitter counts as signer in `execute` only |
| L19 | Lead | Non-monotonic `ExecutionSuccess` events from `executeQueued` | — | 1 | Accepted — indexers must handle out-of-order nonces |
| L20 | Lead | ERC-1271 message approvals revive on owner re-addition | 64 | 1 | Informational — rotate to fresh key instead of re-adding same address |

---

## Findings

### [F-1] MEDIUM — Pre-fund theft via zero-prefix CREATE2 salt front-running [agents: 1]

**Contract:** MultisigFactory
**Function:** `create()` (line 280–300)
**Bug class:** front-running / pre-fund-theft

**Description:** The factory allows salts where `salt >> 96 == 0`, meaning any caller can deploy to the same deterministic address. If a user computes the address off-chain, pre-funds it with ETH, and uses a zero-prefix salt, an attacker can front-run the deployment with different owners and steal the pre-funded ETH.

**Proof:**
```solidity
// zero-prefix salt allows anyone to use it
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
**Function:** `execute()` (lines 134–174)
**Bug class:** pre-validation-external-call

**Description:** When the executor address has its top 2 bytes matching `0x1111` (line 139: `uint160(_executor) >> 144 == 0x1111`), an external call `Multisig(payable(_executor)).execute(target, value, data, sigs)` fires at line 139 BEFORE signature verification at lines 141–157. Any caller can forward arbitrary unvalidated parameters to the executor contract. If the executor is a Multisig where the calling contract is set as its executor, the forwarded call executes without signature validation on either side. EVM atomicity means the entire transaction reverts if the subsequent sig check fails, so state changes don't persist for unauthorized callers — but when `msg.sender == executor`, the sig check is skipped entirely and both the pre-hook call and local execution proceed.

**Confidence:** 90

**Developer response:** Acknowledged — this is the intentional guardian/ban-check pattern. The executor contract is a trusted guardian that needs to see (and potentially revert) transactions BEFORE they are authorized, acting as a blocklist or policy enforcer. The pre-auth ordering is by design.

---

### [F-3] MEDIUM — Queued transactions had no cancellation mechanism [agents: 7] — PARTIALLY RESOLVED

**Contract:** Multisig
**Function:** `executeQueued()` (line 188)
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

**Residual risk:** When `delay > 0` and `executor == address(0)`, queued transactions are irrevocable. No cancel path exists — `cancelQueued` requires the executor, `setDelay(0)` via `onlySelf` is itself timelocked, and the multisig calling `cancelQueued` on itself via `execute` → `target.call` results in `msg.sender = address(this)`, not `executor`. Signer rotation does not help because `executeQueued` performs no signature re-validation. **Accepted as a valid configuration:** irrevocable delay is a deliberate security posture — it reduces trust surface (no executor key to compromise) and still provides a warning window for affected protocols.

---

### [F-4] LOW — `executeQueued` callable by anyone [agents: 7]

**Contract:** Multisig
**Function:** `executeQueued()` (line 188)
**Bug class:** missing-access-control

**Description:** `executeQueued` has no access control. Once a transaction's ETA has passed, any address can trigger execution. This enables MEV extraction on the execution and removes owners' ability to choose execution timing.

**Gate evaluation:** Gate 3 clears (unprivileged), but Gate 4 impact is typically dust-level (timing advantage, not direct fund theft). DEMOTE.

**Confidence:** 65

**Developer response:** Intentional for relayer compatibility — anyone can relay a queued transaction once the delay has passed. The new `cancelQueued` (executor-only) provides the emergency brake if needed.

---

### [F-5] LOW — Post-execution hook fires even when transaction is only queued [agents: 2]

**Contract:** Multisig
**Function:** `execute()` (lines 170–173)
**Bug class:** logic-error

**Description:** The post-hook at lines 170–173 fires unconditionally after the execute/queue branching logic. When `delay > 0` and the transaction is only queued (not executed), the post-hook still calls `executor.execute(target, value, data, sigs)`, forwarding the queued transaction's parameters to the executor contract.

**Confidence:** 75

**Developer response:** Acknowledged — intentional. Since the post-hook is in the same atomic transaction, the guardian can inspect the queued parameters and revert the entire transaction (including the queue write) if policy is violated. This acts as a veto on queuing itself.

---

### [F-6] LOW — Both pre-hook and post-hook fire for crafted executor address [agents: 5]

**Contract:** Multisig
**Function:** `execute()` (lines 139, 170–173)
**Bug class:** double-invocation

**Description:** The pre-hook (line 139: `uint160(_executor) >> 144 == 0x1111`) and post-hook (line 170: `uint160(_executor) & 0xFFFF == 0x1111`) check non-overlapping bits and are not mutually exclusive. An executor address satisfying both (e.g., `0x1111...1111`) triggers `executor.execute()` twice per transaction.

**Confidence:** 75

**Developer response:** Acknowledged — intentional dual-hook design. Pre-hook is for blocking/banning, post-hook is for notification/veto. Both firing for a guardian address is the intended behavior.

---

## Leads

_High-signal trails for manual review. Not scored._

- **[L1] Executor bypasses both signatures and timelock** — `Multisig.execute` — The executor skips signature verification (line 141) AND the timelock delay (line 160). A compromised executor key has unilateral, immediate control. **Assessment:** By design. The executor is an intentionally trusted module (Safe-like pattern). Users who set an executor accept this trust assumption. Consistent with the guardian architecture where the executor is a privileged emergency key.

- **[L2] Executor can burn nonces to invalidate owner signatures; cancelled queued txs create permanent nonce gaps** — `Multisig.execute` — The executor can call `execute()` with dummy parameters to increment nonces, invalidating pre-signed owner transactions. Additionally, nonce is consumed unconditionally at the top of `execute()` before the queue/execute branch (line 136). When a queued transaction is later cancelled via `cancelQueued()`, the nonce is permanently burned — `executeQueued` does not advance the nonce, so cancelled slots leave gaps. Pre-signed batches assuming sequential nonce execution are invalidated if any earlier queued tx is cancelled, forcing re-signing of the entire tail. **Assessment:** Subset of executor trust (nonce burn). The cancel-gap behavior is an operational consideration for batch governance workflows, not a security vulnerability.

- **[L3] Unsafe uint16 downcast of threshold** — `Multisig.init` — `threshold = uint16(_threshold)` and `ownerCount = uint16(len)` silently truncate values above 65535. **Assessment:** Requires 65,536+ owners. Gas cost of writing that many storage slots exceeds any chain's block limit. Unreachable.

- **[L4] Signature malleability (no low-s check)** — `Multisig.isValidSignature` / `Multisig.execute` — Raw `ecrecover` without `s <= secp256k1n/2` check. Both `(v, r, s)` and `(v', r, n-s)` recover the same address. **Assessment:** The sorted-signer ordering (`signer > prev`) prevents internal double-counting. External protocols using signature bytes as dedup keys could be affected, but this is a downstream concern.

- **[L5] uint32 nonce overflow** — `Multisig.execute` — `nonce` is `uint32` incremented in `unchecked`, wrapping after ~4 billion executions. **Assessment:** Impractical on L1. On L2 with a compromised executor burning nonces, still requires billions of transactions at gas cost exceeding any economic incentive.

- **[L6] Stale executor reference in post-hook** — `Multisig.execute` — Executor is cached at function entry (line 136). If the executed transaction changes the executor via `setExecutor`, the post-hook uses the stale (old) address. **Assessment:** Accepted. The post-hook firing on the old executor during a single atomic tx that changes the executor is a known edge case with limited impact.

- **[L7] No reentrancy guard on execute** — `Multisig.execute` — Pre/post hooks and `target.call` enable reentrant `execute()` calls, each consuming a fresh nonce. **Assessment:** Accepted. The executor is trusted, and non-executor reentrant calls still require valid signatures for each new nonce.

- **[L8] Uninitialized implementation contract** — `MultisigFactory` — The implementation deployed by the factory constructor is never initialized. Initialization is provably impossible: (1) `init()` requires `msg.sender == factory || msg.sender == address(this)` (line 40); (2) the factory only calls `init` on clones (line 298), never on the implementation; (3) the implementation cannot call itself because `execute()` reverts when `threshold == 0` (line 145) — circular dependency. Holds no funds by design.

- **[L9] `batch()` missing array length validation** — `Multisig.batch` — No check that `targets`, `values`, and `datas` arrays have equal lengths. Solidity's ABI decoder reverts on out-of-bounds access. UX issue only.

- **[L10] `addOwner` breaks sorted-order invariant** — `Multisig.addOwner` — `init()` enforces ascending address order but `addOwner()` prepends to the list head. On-chain signature verification is unaffected (checks ascending signature order, not list order). Off-chain tooling relying on `getOwners()` for signature assembly may need to sort independently.

- **[L11] `msg.value` not earmarked when transaction is queued** — `Multisig.execute` — ETH sent with a queued `execute()` call is absorbed into the contract's general balance. The queued transaction uses whatever balance exists at execution time. Design tradeoff — the multisig is expected to hold ETH.

- **[L12] EIP-7702 EOA key remains a superuser** — `Multisig.init` / `Multisig.execute` — In an EIP-7702 deployment, the delegating EOA's private key retains full authority: it can send regular transactions bypassing the multisig, satisfy `msg.sender == address(this)` for `onlySelf` functions, and revoke the delegation at any time. This means the k-of-n threshold is not a hard security boundary — the EOA key is an implicit (k=1) override. **Assessment:** Inherent property of EIP-7702, not a contract bug. The README documents this: "The EOA private key remains a superuser." Suited for personal wallets (co-signing), not shared custody. Deployment-model caveat, not an unprivileged attack path against clone-based wallets.

- **[L13] Fallback silently succeeds for unknown selectors** — `Multisig.fallback` (lines 256–264) — The fallback only handles three token-callback selectors (`onERC721Received`, `onERC1155Received`, `onERC1155BatchReceived`). For any other selector, execution falls through the `if` block with no `revert`, returning success with empty returndata. A threshold-signed `execute(address(this), 0, abi.encodeWithSelector(0xdeadbeef), sigs)` succeeds silently as a no-op. In `batch`, a mistyped self-call selector succeeds without reverting, potentially masking operator mistakes in multi-step governance transactions. **Assessment:** Not exploitable — requires threshold signatures or executor. Informational ergonomics risk. The Solady `Receiver.sol` pattern this is adapted from behaves identically. Minimal fix: add a default `revert` after the token-callback `if` block, or document the behavior and rely on off-chain tooling to catch selector typos.

- **[L14] `isValidSignature` uses `SafeMessage(bytes32 hash)`, not Safe's `SafeMessage(bytes message)`** — `Multisig.isValidSignature` (lines 107–132) — The function wraps the supplied hash in an EIP-712 `SafeMessage(bytes32 hash)` typed-data digest. Safe's `CompatibilityFallbackHandler` uses `SafeMessage(bytes message)` with dynamic `bytes` encoding. Same pattern, different type hash — signatures produced by the Safe UI/SDK will not validate here. **Assessment:** Intentional. This wallet has its own signing domain. Integrators must use the correct type hash. Not a vulnerability.

- **[L15] No ERC-1271 inline signature verification** — `Multisig.isValidSignature` / `Multisig.execute` — Contract addresses can be added as owners. ERC-1271 inline verification is omitted from the signature loop — contract owners participate via `approve(hash, true)` (onchain approval) or `msg.sender` bypass (`v=0` with the contract as the submitter). **Assessment:** Intentional — avoids external calls in the sig loop. The approval + sender bypass pattern covers all account types without ERC-1271.

- **[L16] `executeQueued` does not re-validate signer set** — `Multisig.executeQueued` (lines 188–199) — Between queue time and execution time, the owner set can change via `addOwner`/`removeOwner`. `executeQueued` recomputes the hash and checks the ETA but never re-checks that the original signers are still owners. The transaction was authorized by a signer set that may no longer exist. **Assessment:** Accepted. Re-validation would require storing signatures on-chain (expensive). The delay window + `cancelQueued` (if executor is set) is the intended mitigation. Configurations without an executor accept irrevocable queued transactions as a deliberate trust tradeoff.

- **[L17] Pre/post hook return values silently discarded** — `Multisig.execute` (lines 139, 171) — The external calls to the executor's `execute` function discard return values. A guardian contract that signals rejection via a return value (rather than reverting) is silently ignored. **Assessment:** Accepted — revert-based enforcement is the intended pattern. Implicit interface contract, but consistent with Solidity guard conventions (e.g., OpenZeppelin hooks).

- **[L18] v=0 `msg.sender` bypass asymmetry between `execute()` and `isValidSignature()`** — `Multisig.execute` (line 150) / `Multisig.isValidSignature` (line 123) — In `execute()`, the v=0 approval path includes `require(msg.sender == signer || approved[signer][hash])`, allowing the transaction submitter to count as one of the threshold signers without having called `approve()` first. In `isValidSignature()`, the v=0 path only checks `require(approved[signer][safe])` — no `msg.sender` bypass. This means `execute()` has an effective threshold of `threshold - 1` additional signatures when the submitter is an owner, while `isValidSignature()` always requires `threshold` explicit approvals. **Assessment:** Intentional. The `msg.sender` bypass is the mechanism by which an owner submitting the transaction "signs" by virtue of being the caller. The ERC-1271 path requires explicit pre-approval because there is no interactive caller to attribute. The asymmetry is a feature, not a bug, but integrators should be aware that ERC-1271 validation is strictly stronger than `execute()` authorization.

- **[L19] Non-monotonic `ExecutionSuccess` events from `executeQueued`** — `Multisig.executeQueued` (line 197) — `executeQueued` emits `ExecutionSuccess(hash, _nonce)` where `_nonce` is the caller-supplied historical nonce from queue time. Since `execute()` may have advanced the on-chain nonce well past this value, events from `executeQueued` appear out-of-order relative to events from `execute()`. Example: nonces 5, 6, 7 are queued; nonce 8 executes immediately; then nonce 5 is dequeued — events arrive as `[..., 8, 5]`. **Assessment:** Accepted. The hash commits to the nonce so the caller-supplied value is validated. Off-chain indexers tracking `ExecutionSuccess` events must not assume monotonic nonce ordering.

- **[L20] ERC-1271 message approvals revive on owner re-addition** — `Multisig.isValidSignature` (lines 107–132) / `Multisig.approve` (line 176) / `Multisig.removeOwner` (line 227) / `Multisig.addOwner` (line 217) — The `approved[owner][hash]` mapping entry persists when an owner is removed via `removeOwner`. While removed, `isValidSignature` rejects the approval because `_owners[signer] != address(0)` fails (line 127). But if the same address is later re-added via `addOwner`, the ownership check passes again and the historical approval silently revives. Unlike `execute` hashes (which include `nonce` and are invalidated by the nonce advances that accompany owner-management transactions), `isValidSignature` message hashes use `SafeMessage(bytes32 hash)` wrapping with no nonce component — they are static. **Assessment:** Informational. Requires: (1) a historical `approve` or ECDSA signature for a specific message hash, (2) owner removal, (3) re-addition of the *same* address, (4) the rest of the threshold still being satisfied. Not exploitable by an external attacker. Operational mitigation: rotate to a fresh key address instead of re-adding a previously removed address.

---

## Changes Made

| Change | Commit | Description |
|--------|--------|-------------|
| `cancelQueued(bytes32)` | `5c2991a` | Executor-only emergency cancellation for queued transactions. Partially resolves F-3 (requires executor). |
| Pre/post guards in `executeQueued` | `5811239` | `executeQueued` now triggers the same vanity-address pre/post guard calls as `execute` (empty sigs). Extends scope of F-2, F-5, F-6 to cover the queued execution path. |
| `cancelQueued` event | (pending) | `cancelQueued` now emits `Queued(hash, 0, 0)` for indexer visibility. `eta = 0` signals cancellation. |

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

**Third-party review (2026-04-03):** Two-pass independent GPT-4.5 review following the SECURITY.md methodology. First pass: structural compliance but lacked line-level citations; confirmed 0 new scoreable findings and surfaced L12 (EIP-7702 EOA key superuser). Second pass: full function-by-function walkthrough with line citations and cross-function attack analysis; confirmed all invariants, surfaced L13 (fallback silent success for unknown selectors). Both passes reached correct conclusions; the second pass met the methodology's depth requirements.

**Fourth pass (2026-04-03):** Fresh 3-agent Opus/Sonnet parallelized re-audit (Vector Scan, Access Control, Math/Invariants/Economic). Confirmed all existing findings. Surfaced two new leads: L18 (v=0 `msg.sender` bypass asymmetry between `execute` and `isValidSignature`) and L19 (non-monotonic `ExecutionSuccess` events from `executeQueued`). Enhanced L2 with the cancelled-queued-tx nonce gap analysis. Multiple agents flagged the `delegateCall` → zero-threshold → re-init chain as "critical," but this was correctly demoted: it requires threshold-of-owners who can already drain funds directly via any `execute` call, making it tautological. No new scoreable findings above Lead severity.

---

## Disclaimer

This report was generated using an AI-powered parallelized audit framework. AI-assisted audits are a preliminary check and should not be considered a substitute for a formal manual security review by experienced auditors. Always conduct thorough testing, formal verification, and professional audits before deploying smart contracts to mainnet.
