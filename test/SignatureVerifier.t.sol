// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/SignatureVerifier.sol";

contract WhiteListERC20 is ERC20 {
    constructor() ERC20("WEBCXII", "WCXII") {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }
}

contract SignatureVerifierTest is Test {
    SignatureVerifier public verifier;
    WhiteListERC20 public token;
    address public whitelistedUser;
    uint256 public whitelistedUserPrivateKey;

    function setUp() public {
        token = new WhiteListERC20();
        whitelistedUserPrivateKey = 0xA11CE;
        whitelistedUser = vm.addr(whitelistedUserPrivateKey);

        address[] memory whitelist = new address[](1);
        whitelist[0] = whitelistedUser;

        verifier = new SignatureVerifier(address(token), whitelist);
        token.transfer(address(verifier), 1000 * 10 ** 18);
    }

    function testVerifyAndClaim() public {
        bytes32 messageHash = keccak256("Claim tokens");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(whitelistedUserPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(whitelistedUser);
        verifier.verifyAndClaim(messageHash, signature);

        assertEq(token.balanceOf(whitelistedUser), 100 * 10 ** 18);
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
