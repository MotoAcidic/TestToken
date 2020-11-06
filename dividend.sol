pragma solidity ^0.4.21;

import "./Ownable.sol";

contract CatThis is Ownable {

    string public name = "CatThis";
    string public symbol = "CATS";
    uint8 public decimals = 18;
    uint blocksAday = 6500; // Rough rounded up blocks perday based on 14sec eth block time
    uint public rewardPerDay = 50e18; // Amount perday you can claim from the dividend
    uint public minNodeamount = 5000e18; // Min amount to needed to claim dividend
    address public owner = msg.sender;
    uint256 public scaling = uint256(10) ** 8;
    uint256 public scaledRemainder = 0;
    uint256 public scaledDividendPerToken = blocksAday / rewardPerDay; // Calc for the reward to equal only 50 coins paid out perday
    uint256 public totalSupply = 21000000e18; //21m coins

    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public scaledDividendBalanceOf;
    mapping(address => uint256) public scaledDividendCreditedTo;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() public {
        // Initially assign all tokens to the contract's creator.
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }
    
    // ------------------------------------------------------------------------
    // Change Required Tokens
    // ------------------------------------------------------------------------
    function changeRequiredTokens(uint _value) public {
        minNodeamount = _value;
    }
    
    // ------------------------------------------------------------------------
    // Change reward amount
    // ------------------------------------------------------------------------
    function changeNodeReward(uint _value) public {
        rewardPerDay = _value;
    }

    function update(address account) internal {
        if (balanceOf[account] >= minNodeamount){
        uint256 owed =
            scaledDividendPerToken - scaledDividendCreditedTo[account];
        scaledDividendBalanceOf[account] += balanceOf[account] * owed;
        scaledDividendCreditedTo[account] = scaledDividendPerToken;
        }
    }

    function transfer(address to, uint256 value) public returns (bool success) {
        require(balanceOf[msg.sender] >= value);

        update(msg.sender);
        update(to);

        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;

        emit Transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value)
        public
        returns (bool success)
    {
        require(value <= balanceOf[from]);
        require(value <= allowance[from][msg.sender]);

        update(from);
        update(to);

        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }
    

    function deposit() public payable {
        // scale the deposit and add the previous remainder
        uint256 available = (msg.value * scaling) + scaledRemainder;

        scaledDividendPerToken += available / totalSupply;

        // compute the new remainder
        scaledRemainder = available % totalSupply;
    }

    function withdraw() public {
        update(msg.sender);
        uint256 amount = scaledDividendBalanceOf[msg.sender] / scaling;
        scaledDividendBalanceOf[msg.sender] %= scaling;  // retain the remainder
        msg.sender.transfer(amount);
    }

    function approve(address spender, uint256 value)
        public
        returns (bool success)
    {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

}