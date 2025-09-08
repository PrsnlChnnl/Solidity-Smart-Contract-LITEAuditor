// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Контракт с реальными уязвимостями для тестирования
contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Уязвимость: отсутствие проверки прав
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }
    
    // Уязвимость: reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // Нарушен паттерн Checks-Effects-Interactions
        balances[msg.sender] -= amount;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Уязвимость: неправильное именование переменной
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}