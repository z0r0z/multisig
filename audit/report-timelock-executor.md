# TimelockExecutor Module Security Audit Report

**Date:** 2026-04-04
**Target:** `src/mods/TimelockExecutor.sol` + integration with `src/Multisig.sol`
**Method:** Pashov Skills — 8-vector security audit with gate evaluation
**Solidity:** ^0.8.34

---

## Scope

| Contract | Lines | Description |
|---|---|---|
| `TimelockExecutor` | 71 | Stateless singleton executor module: sig-verified cancel (threshold) + forward (unanimous) + accelerate (unanimous self-call to executeQueued) |

### Architecture

TimelockExecutor is a **singleton** executor module with minimal state (`forwardEnabled` mapping only). A Multisig sets `executor = address(timelockExecutor)`, granting the module the ability to call `execute(target, value, data, "")` on that Multisig without signatures.

The module uses the **same EIP-712 `Execute` typehash** as the Multisig itself. Signatures are interchangeable — the UI routes based on count:

| Signatures | Route | Result |
|---|---|---|
| Threshold | `Multisig.execute()` | Queued with timelock |
| Threshold + cancelQueued selector | `TimelockExecutor.forward()` | Immediate cancel |
| All owners | `TimelockExecutor.forward()` | Immediate execution (opt-in) |
| All owners + executeQueued self-call | `TimelockExecutor.forward()` | Accelerate queued tx (opt-in) |

### Multisig Changes Under Review

Two changes to `Multisig.sol` support this module:

1. `cancelQueued` changed from `require(msg.sender == executor)` to `onlySelf` — cancel now routes through `execute` as a self-call
2. `executeQueued` ETA bypass: `msg.sender == address(this)` skips the `block.timestamp >= eta` check — self-calls can accelerate queued txs

---

## Summary

| # | Severity | Title | Confidence | Status |
|---|----------|-------|------------|--------|
| 1 | Low | Threshold-signed cancel sigs are dual-use with `Multisig.execute()` | 60 | Acknowledged — by design |
| 2 | Low | `enableForward` cannot be toggled without executor cooperation | 55 | Acknowledged — multisig is the executor's principal |
| 3 | Low | Forward burns a nonce even for cancel path | 50 | Acknowledged — inherent to executor `execute()` path |
| L1 | Lead | Malicious `multisig` address could return crafted values | — | Not exploitable — attacker only attacks themselves |
| L2 | Lead | `ecrecover` returns `address(0)` on invalid sig | — | Handled — `isOwner(address(0))` returns false |
| L3 | Lead | `required * 65` overflow in `unchecked` | — | Safe — `required` is uint16 max 65535 |
| L4 | Lead | Self-call `executeQueued` bypass could be triggered by delegatecall | — | Mitigated — delegatecall changes storage context, not `address(this)` |

---

## Findings

### [F-1] LOW — Threshold-signed cancel sigs are dual-use with `Multisig.execute()`

**Function:** `forward()` (line 40–46) / `Multisig.execute()` (line 134–174)
**Bug class:** sig-reuse

**Description:** Cancel sigs are signed over `Execute(multisig, 0, cancelQueued(hash), nonce)` with exactly `threshold * 65` bytes. These same sigs are also valid for `Multisig.execute()` — the Multisig expects `threshold * 65` bytes and would accept them. If submitted directly to `execute()`, the cancel call would be *queued* behind the timelock instead of executing immediately.

**Impact:** An attacker who intercepts cancel sigs could submit them to `execute()` instead of `forward()`, causing the cancel to be timelocked rather than immediate. However:
- The nonce is consumed either way — the cancel still happens, just delayed
- The attacker cannot change the call target or data (sigs are bound to them)
- If submitted to `forward()` first, the nonce is consumed and `execute()` reverts

**Confidence:** 60

**Response:** Acknowledged — by design. The same typehash is intentional for UX. Whoever submits first wins the race. The worst outcome is a delayed cancel, which is strictly less harmful than no cancel. The module path is preferred but the fallback (timelocked cancel) is still safe.

---

### [F-2] LOW — `enableForward` cannot be toggled without executor cooperation

**Function:** `enableForward()` (line 29–32)
**Bug class:** access-control coupling

**Description:** `enableForward` is keyed by `msg.sender`, so the multisig must call it via `execute`. Since `execute` goes through the executor (TimelockExecutor) when the executor is set, the multisig cannot toggle `enableForward` without the executor's cooperation — the executor must call `execute(timelockExecutor, 0, enableForward(true), "")` on behalf of the multisig.

However, `enableForward` is typically configured at deployment via `createWithCalls`. Post-deployment changes require a threshold-signed `execute` targeting the module, which the executor relays. Since the executor faithfully relays any `execute` call, and owners control what they sign, this is not a real blocker.

**Confidence:** 55

**Response:** Acknowledged. Owners sign the `enableForward` call like any other transaction. The executor relays it without modification. If the executor is changed away from TimelockExecutor, `enableForward` state is inert.

---

### [F-3] LOW — Forward burns a nonce even for cancel path

**Function:** `forward()` (line 68) → `Multisig.execute()`
**Bug class:** resource-consumption

**Description:** Every `forward()` call ends with `IMultisig(multisig).execute(target, value, data, "")`, which increments the Multisig's nonce. For the cancel path, this means cancelling a queued tx consumes a nonce — any off-chain signatures prepared for that nonce become invalid.

This is inherent to the executor-bypass design: `execute()` always increments the nonce. A dedicated `cancelQueued()` call (the old design) did not burn a nonce. The tradeoff is architecture simplicity (single path through `execute`) vs. nonce conservation.

**Confidence:** 50

**Response:** Acknowledged. The nonce burn is inherent to routing cancel through `execute`. The benefit (same typehash, stateless module, single execution path) outweighs the cost. UIs should account for nonce advancement when a cancel is submitted.

---

## Leads

_High-signal trails for manual review. Not scored._

- **[L1] Malicious `multisig` address** — A caller could pass a crafted contract as `multisig` that returns manipulated values from `nonce()`, `threshold()`, `isOwner()`, etc. However, the final `execute()` call targets the same address. The attacker would only be executing calls on their own malicious contract. No impact on real multisigs. Singleton state (`forwardEnabled`) is keyed by the real multisig address — the attacker cannot toggle it for a victim.

- **[L2] `ecrecover` returns `address(0)` on invalid sig** — If `ecrecover` returns `address(0)` due to an invalid signature, the subsequent `isOwner(address(0))` check fails because `_owners[address(0)]` is zero by default and `address(0) != SENTINEL`. The invalid sig is correctly rejected.

- **[L3] `required * 65` overflow in `unchecked`** — The `require(sigs.length == required * 65)` check is inside the `unchecked` block. `required` comes from `threshold()` or `ownerCount()`, both `uint16` (max 65535). `65535 * 65 = 4,259,775` — well within `uint256`. No overflow possible.

- **[L4] Self-call `executeQueued` bypass via delegatecall** — The `executeQueued` ETA bypass checks `msg.sender == address(this)`. Could an attacker use `delegateCall` to make `address(this)` match? No — `delegateCall` changes the storage context but `address(this)` still refers to the contract whose code is executing. A delegatecall into the Multisig from another contract would have `address(this) == callerContract`, not `address(multisig)`. The queued hash (keyed by the Multisig's domain separator) wouldn't match either.

---

## Integration Analysis: TimelockExecutor ↔ Multisig

### Execution Flows

**Cancel flow:**
```
Submitter → TimelockExecutor.forward(multisig, multisig, 0, cancelQueued(hash), thresholdSigs)
  → require(selector == cancelQueued)         [cancel path]
  → required = threshold()
  → hash = getTransactionHash(multisig, 0, cancelQueued(hash), nonce)
  → verify threshold sigs over hash
  → execute(multisig, 0, cancelQueued(hash), "")  [executor bypass]
    → Multisig nonce++ (consumed)
    → Multisig self-call → cancelQueued(hash)  [onlySelf passes]
    → delete queued[hash]
```

**Forward flow:**
```
Submitter → TimelockExecutor.forward(multisig, target, value, data, allOwnerSigs)
  → require(forwardEnabled[multisig])          [forward path]
  → required = ownerCount()
  → hash = getTransactionHash(target, value, data, nonce)
  → verify ownerCount sigs over hash
  → execute(target, value, data, "")           [executor bypass]
    → Multisig nonce++ (consumed)
    → target.call{value}(data)                 [immediate execution]
```

**Accelerate flow:**
```
Submitter → TimelockExecutor.forward(multisig, multisig, 0, executeQueued(target, value, data, queuedNonce), allOwnerSigs)
  → require(forwardEnabled[multisig])          [forward path — not cancel selector]
  → required = ownerCount()
  → hash = getTransactionHash(multisig, 0, executeQueued(...), nonce)
  → verify ownerCount sigs over hash
  → execute(multisig, 0, executeQueued(...), "")  [executor bypass]
    → Multisig nonce++ (consumed)
    → Multisig self-call → executeQueued(target, value, data, queuedNonce)
      → msg.sender == address(this) → skips ETA
      → delete queued[queuedHash]
      → target.call{value}(data)               [queued entry consumed]
```

### Replay Prevention

| Vector | Prevention |
|---|---|
| Same sigs to `forward()` twice | Nonce consumed by `execute()` on first call — hash mismatch on second |
| Same sigs to `execute()` directly | Nonce consumed by whichever path submits first |
| Cross-multisig replay | `DOMAIN_SEPARATOR` includes `address(this)` — different per multisig |
| Cross-chain replay | `DOMAIN_SEPARATOR` includes `block.chainid` |
| Onchain approval reuse | `approved[signer][hash]` — hash includes nonce, inert after consumption |

### Key Invariants

1. **Stateless module** — Only storage is `forwardEnabled`. No voting state, no nonces, no accumulated votes. All replay prevention delegated to the Multisig's nonce.

2. **Same typehash** — `getTransactionHash` produces the identical EIP-712 hash for both `execute()` and `forward()`. Sigs are interchangeable. No signature domain divergence.

3. **Cancel always available** — Cancel path bypasses `forwardEnabled`. Installing TimelockExecutor as executor immediately enables threshold-vote cancel with no additional setup.

4. **Forward opt-in** — `forwardEnabled` gates all non-cancel paths. Multisigs that want cancel-only functionality without timelock bypass simply never enable forward.

5. **Singleton isolation** — `forwardEnabled` keyed by multisig address. `enableForward` keyed by `msg.sender`. One multisig's config cannot affect another's.

6. **Sig verification parity** — The module's verification loop mirrors `Multisig.execute()` exactly: same ECDSA path, same v=0 approval path (sender bypass + onchain approval), same sorted-order requirement, same owner check.

---

## Test Coverage Assessment

| Scenario | Test | Status |
|---|---|---|
| Cancel: threshold sigs cancel queued tx | `test_cancel_thresholdCancels` | Covered |
| Cancel: via createWithCalls | `test_cancel_createWithCalls` | Covered |
| Cancel: insufficient sigs reverts | `test_cancel_revertInsufficientSigs` | Covered |
| Cancel: invalid sig reverts | `test_cancel_revertInvalidSig` | Covered |
| Cancel: works without forwardEnabled | `test_cancel_worksWithoutForwardEnabled` | Covered |
| Cancel: timelock normal path still works | `test_cancel_timelockStillWorks` | Covered |
| Forward: all-owner sigs immediate execute | `test_forward_allOwnersExecute` | Covered |
| Forward: insufficient sigs reverts | `test_forward_revertInsufficientSigs` | Covered |
| Forward: invalid signer reverts | `test_forward_revertInvalidSigner` | Covered |
| Forward: nonce consumed | `test_forward_nonceConsumed` | Covered |
| Forward: replay reverts | `test_forward_revertReplaySameNonce` | Covered |
| Forward: same call twice (fresh nonce) | `test_forward_sameCallTwice` | Covered |
| Forward: reverts without forwardEnabled | `test_forward_revertNotEnabled` | Covered |
| Forward: v=0 onchain approval path | `test_forward_onchainApproval` | Covered |
| Accelerate: queued tx consumed immediately | `test_forward_accelerateQueuedTx` | Covered |
| Forwarded event emitted | `test_forward_emitsForwardedEvent` | Covered |
| enableForward: event emitted | `test_enableForward_emitsEvent` | Covered |
| Multisig: self-call bypasses ETA | `test_executeQueued_selfCallBypassesEta` | Covered |
| Multisig: external caller still waits | `test_executeQueued_externalCallerStillWaits` | Covered |
| Multisig: cancelQueued onlySelf | `test_cancelQueued_viaSelfCall` | Covered |
| Multisig: cancelQueued revert not self | `test_cancelQueued_revertNotSelf` | Covered |

---

## Changes Made

None required. All findings are low-severity acknowledged design tradeoffs.

---

## Methodology

8-vector Pashov Skills audit on TimelockExecutor.sol (71 lines) with full integration analysis against Multisig.sol. Review covered:

1. **Vector Scan** — Reentrancy, replay, front-running, sig reuse across paths
2. **Math Precision** — Overflow in unchecked blocks, uint16 bounds
3. **Access Control** — enableForward gating, executor trust model, singleton keying
4. **Economic Security** — Nonce consumption costs, griefing via path racing
5. **Execution Trace** — Cross-contract call flow, self-call routing, cancel/forward/accelerate paths
6. **Invariant** — Sig verification parity with Multisig, nonce atomicity, domain separation
7. **Periphery** — Vanity address warning, malicious multisig address, ecrecover edge cases
8. **First Principles** — Typehash reuse implications, timelock bypass threat model, enableForward rationale

---

## Disclaimer

This report was generated using an AI-powered security audit framework. AI-assisted audits are a preliminary check and should not be considered a substitute for a formal manual security review by experienced auditors. Always conduct thorough testing, formal verification, and professional audits before deploying smart contracts to mainnet.
