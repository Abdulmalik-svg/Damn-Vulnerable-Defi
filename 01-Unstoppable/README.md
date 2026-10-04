# Unstoppable - Breaking Flash Loans With a Single Token Transfer

**Challenge:** Damn Vulnerable DeFi v4 - Unstoppable
**Category:** Denial of Service / Broken Invariant
**Severity:** High (see reasoning below — my first instinct was Medium, and I think that's wrong)

## What's going on

This vault offers free flash loans on a million DVT tokens. You start with 10 DVT and
nothing else — no admin access, no special permissions. The goal isn't to steal
anything. It's to break the flash loan feature entirely.

Turns out you can do it with one line of code and 10 tokens you don't even lose.

## The bug

Every time `flashLoan()` runs, it checks that the vault's raw token balance lines up
with what its share accounting expects:

```solidity
uint256 balanceBefore = totalAssets(); // = asset.balanceOf(address(this))
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
```

The problem is this only holds true if every token that ever enters the vault comes in
through `deposit()`, since that's the only place shares get minted. But nothing stops
anyone from just sending tokens straight to the vault with a plain `transfer()`. That
bumps the balance up without minting a single share, and the two numbers the vault is
comparing suddenly disagree — permanently.

## The attack

1. Take your 10 DVT and send them directly to the vault: `token.transfer(vault, 10 ether)`.
2. That's it. No deposit, no shares, nothing fancy.
3. Now `balanceOf(vault)` is higher than what `convertToShares(totalSupply)` expects.
4. Every flash loan attempt from here on reverts with `InvalidBalance()`.
5. The monitor contract watching the vault notices the failure, pauses everything, and
   hands ownership back to the deployer. Flash loans are dead until someone manually
   steps in and fixes it.

You can see this play out in the trace — `flashLoan()` reverts, `FlashLoanStatus(false)`
fires, and the vault flips to paused with ownership transferred away from the monitor.

## PoC

The whole exploit is one line inside the test:

```solidity
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), INITIAL_PLAYER_TOKEN_BALANCE);
}
```

Full test file with trace output is in this folder.

## Why I'm calling this High, not Medium

My first instinct was Medium — nobody's funds get stolen, nothing's permanently
locked, this "just" breaks a feature. But sitting with it longer, that framing misses
a few things that actually matter a lot in practice:

- **It doesn't fix itself.** The vault stays paused and flash loans stay dead until the
  owner manually calls `execute()` to repair the accounting. This isn't a temporary
  hiccup — it's broken until a human intervenes.
- **The attacker doesn't even spend anything.** The 10 tokens aren't lost, they're just
  sitting in the vault now. This costs basically nothing beyond gas.
- **Anyone can do it.** No special role, no timing window, no capital requirement.
- **Flash loans aren't a side feature here — they're the product.** And presumably a
  fee source for the protocol. Killing that indefinitely for free is a real problem.

If the vault had some way to self-correct — say, a permissionless function anyone
could call to resync the balance and shares — I'd be comfortable calling this Medium.
It doesn't have one, so I don't think Medium captures the actual impact. This is the
kind of judgment call that's worth being able to defend with reasoning rather than
just asserting a label, since reviewers on real contests will push back on severity
constantly.

## Fix

Stop trusting raw `balanceOf(address(this))` as a source of truth for anything
security-critical if the contract can receive unsolicited transfers. A few ways to
handle it:

- Track deposits with your own internal counter, updated only inside `deposit()` /
  `withdraw()`, instead of reading the live balance.
- Add a permissionless `sync()` or `skim()` function so a stray donation doesn't
  permanently wreck things — worst case it's a minor annoyance instead of a DoS.

## Takeaway

Any time a contract both accepts arbitrary incoming transfers *and* bases important
logic on `balanceOf(address(this))`, this pattern is worth checking for immediately.
It shows up constantly in real protocols, not just CTF-style challenges — it's an easy
thing to miss when writing the code and an easy thing to check for when reading it.
