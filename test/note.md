// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/SignatureVerification.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("MockToken", "MTK") {
        _mint(msg.sender, 1000000 * 10**18);
    }
}

contract SignatureVerificationTest is Test {
    SignatureVerification public verifier;
    MockERC20 public token;
    address public whitelistedUser;
    uint256 public whitelistedUserPrivateKey;

    function setUp() public {
        token = new MockERC20();
        whitelistedUserPrivateKey = 0xA11CE;
        whitelistedUser = vm.addr(whitelistedUserPrivateKey);

        address[] memory whitelist = new address[](1);
        whitelist[0] = whitelistedUser;

        verifier = new SignatureVerification(address(token), whitelist);
        token.transfer(address(verifier), 1000 * 10**18);
    }

    function testVerifyAndClaim() public {
        bytes32 messageHash = keccak256("Claim tokens");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(whitelistedUserPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(whitelistedUser);
        verifier.verifyAndClaim(messageHash, signature);

        assertEq(token.balanceOf(whitelistedUser), 100 * 10**18);
    }

    function testFailNonWhitelisted() public {
        address nonWhitelisted = address(0x1234);
        bytes32 messageHash = keccak256("Claim tokens");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(nonWhitelisted);
        verifier.verifyAndClaim(messageHash, signature);
    }

    function testFailDoubleClaim() public {
        bytes32 messageHash = keccak256("Claim tokens");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(whitelistedUserPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.startPrank(whitelistedUser);
        verifier.verifyAndClaim(messageHash, signature);
        verifier.verifyAndClaim(messageHash, signature);
        vm.stopPrank();
    }
}


 function verifyAndClaim(bytes32 messageHash, bytes memory signature) external {
        address signer = messageHash.recover(signature);
        require(whitelist[signer], "Address not whitelisted");
        require(signer == msg.sender, "Signer must be the sender");
        require(!hasClaimed[signer], "Tokens already claimed");

        hasClaimed[signer] = true;
        require(token.transfer(signer, 100 * 10**18), "Token transfer failed");
    }