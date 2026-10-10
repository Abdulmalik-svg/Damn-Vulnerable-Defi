# Withdrawal - An Unchecked Call Result Behind a Privileged Shortcut

**Challenge:** Damn Vulnerable DeFi v4 - Withdrawal
**Category:** Unchecked External Call / Privileged Proof Bypass
**Severity:** Critical (a near-total bridge drain gets marked "finalized" with the underlying transfer silently reverted, and the operator shortcut lets an attacker force that outcome on demand)

## What's going on

An L1↔L2 token bridge finalizes withdrawals through a Merkle-proof-gated gateway:
each withdrawal is `(nonce, l2Sender, target, timestamp, message)`, hashed into a leaf
and checked against a root set by the owner. Four real withdrawals were recorded on
L2 — three for 10 DVT each, and one for 999,000 DVT, almost the entire 1,000,000 DVT
bridge balance. The player holds the gateway's `OPERATOR_ROLE`. The goal: get all four
marked `finalized` (the success condition explicitly checks all four leaves), while the
bridge keeps at least 99% of its funds and the player ends up holding nothing extra.

Those two requirements only coexist if the huge withdrawal gets marked finalized
**without its transfer actually happening.**

## The bugs

**1. The external call's result is never checked.** `L1Gateway.finalizeWithdrawal`
updates all its bookkeeping before making the call, and reads `success` into a local
variable that's only ever logged, never acted on:

```solidity
finalizedWithdrawals[leaf] = true;
counter++;
...
bool success;
assembly {
    success := call(gas(), target, 0, add(message, 0x20), mload(message), 0, 0)
}
...
emit FinalizedWithdrawal(leaf, success, isOperator);
```

If the downstream call reverts for any reason, the leaf is still marked finalized and
the counter still increments - "finalized" and "funds actually moved" are not the same
thing here, and nothing enforces that they should be.

**2. Operators skip proof verification entirely - for arbitrary data.** The Merkle
check only runs for non-operators:

```solidity
bool isOperator = hasAnyRole(msg.sender, OPERATOR_ROLE);
if (!isOperator) {
    if (MerkleProof.verify(proof, root, leaf)) { ... } else { revert InvalidProof(); }
}
```

An operator can call `finalizeWithdrawal` with **any** `(nonce, l2Sender, target,
timestamp, message)` tuple of their choosing - not just ones that were ever actually
queued on L2. Nothing about that privilege is scoped to "skip proving a withdrawal you
already know is real"; it's "execute literally anything."

## How the two bugs combine

`TokenBridge.executeTokenWithdrawal` does `totalDeposits -= amount;` under Solidity
0.8's checked arithmetic. If an attacker (as operator) first forges and finalizes a
small, *real* withdrawal of their own - one that legitimately routes through
`L1Forwarder → TokenBridge` and actually transfers funds - they can drain just enough
of `totalDeposits` to push it below the 999,000 DVT the big real withdrawal needs.
When that big withdrawal is then finalized, the arithmetic underflows and the inner
call reverts - silently, thanks to bug #1 - so the leaf is marked finalized with zero
tokens moved.

## The attack

1. As operator, finalize a forged withdrawal routing `l2Handler → L1Forwarder →
   TokenBridge.executeTokenWithdrawal(dump, 1_001e18)`. No proof required. This really
   transfers 1,001 DVT out (well under the 1% loss the success check tolerates),
   dropping `totalDeposits` to ~998,999 DVT.
2. Finalize the four genuine withdrawals exactly as recorded on L2 (read straight from
   the real event log data, not retyped by hand). The three 10-DVT ones succeed
   normally. The 999,000-DVT one's inner `totalDeposits -= amount` now underflows and
   reverts — but `L1Gateway` never checks that, so `finalizedWithdrawals[leaf]` is set
   to `true` and `counter` increments anyway.

Result: all four required leaves are `true`, the bridge retains 99.9% of its balance,
and the player holds zero tokens.

## PoC (excerpt)

```solidity
// 1. Forged, but genuinely executed, small withdrawal — drains just enough
//    totalDeposits to make the real large withdrawal underflow later.
bytes memory forgedInner = abi.encodeCall(TokenBridge.executeTokenWithdrawal, (dump, 1_001e18));
bytes memory forgedOuter =
    abi.encodeCall(L1Forwarder.forwardMessage, (9999, l2Handler, address(l1TokenBridge), forgedInner));
l1Gateway.finalizeWithdrawal(9999, l2Handler, address(l1Forwarder), START_TIMESTAMP, forgedOuter, new bytes32[](0));

// 2. Finalize the four real withdrawals exactly as recorded on L2.
//    The 999,000 DVT one reverts internally but is still marked finalized.
for (uint256 i = 0; i < entries.length; i++) {
    l1Gateway.finalizeWithdrawal(nonce, l2Sender, target, timestamp, message, new bytes32[](0));
}
```

Full test file: `test/withdrawal/Withdrawal.t.sol`

## Why I'm calling this Critical

- **"Finalized" stops meaning anything.** The entire point of a withdrawal-finalization
  record is to be a reliable audit trail of what actually happened; here it can be made
  true for withdrawals that moved zero funds.
- **The operator shortcut has no scope.** It was clearly meant to let a trusted relayer
  skip re-proving something already known to be valid — not to grant arbitrary-data
  execution power with the gateway's 7-day delay as the only remaining check.
- **The two issues compound into an active attack, not just a passive risk.** An
  operator can deliberately engineer the underflow on demand against a specific target
  withdrawal, rather than this only mattering if a call happens to fail for unrelated
  reasons.
- **The downstream consequences are silent.** A large legitimate withdrawal appears
  processed everywhere an indexer or monitoring system would check (`finalized ==
  true`, `counter` incremented, event emitted) while the actual funds never moved —
  exactly the kind of state a real user or auditor would trust without digging further.

## Fix

- **Check the call's result and revert, or explicitly track failure, instead of
  silently continuing.** At minimum: `if (!success) revert WithdrawalFailed(leaf);` -
  or, if partial-failure handling is genuinely intended, only mark `finalized` on
  success and expose a separate, honest "attempted but failed" state (the way
  `L1Forwarder` does with its own `successfulMessages`/`failedMessages` split).
- **Scope the operator bypass narrowly.** If operators exist to skip redundant proof
  checks, require the withdrawal to still have been recorded somewhere verifiable (e.g.
  against a second, operator-specific root, or logged and checked against L2 state)
  rather than accepting fully arbitrary calldata.
- Consider requiring operator-finalized withdrawals to go through the same proof check
  but against a faster-updating "pending" root, rather than bypassing verification
  altogether.

## Takeaway

Two patterns worth carrying into real audits from this one. First: any low-level `call`
whose `success` is captured but not acted on is a silent-failure bug waiting for a
trigger - search for `success :=` or `(bool success, ) = ... .call(...)` followed by no
`require`/`revert`. Second: a role meant to "skip a redundant check" is easy to
over-scope into "skip *all* checks" - audit exactly what a privileged bypass actually
grants, not just what it was presumably intended for. Combined, these two patterns let
an attacker engineer exactly the external-call failure they need, on demand, and have
the system record it as a success anyway.
