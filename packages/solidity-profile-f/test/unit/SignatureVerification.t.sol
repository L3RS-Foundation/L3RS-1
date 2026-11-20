// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Direct unit tests for the SignatureVerification library. The library is
// exercised transitively by every governance-quorum path in the codebase, but
// `verifySingle` has no transitive call site today and must be tested directly.
// Source: DESIGN.md §8.2, §12 6A priority 1.

import {Test} from "forge-std/Test.sol";
import {SignatureVerification} from "../../src/libraries/SignatureVerification.sol";

/// @dev Thin contract wrapper so we can call the `internal` library functions
///      under a distinct address and exercise the `address(this)` semantics.
contract SignatureVerificationHarness {
    SignatureVerification.GovernanceAuthoritySet internal _authorities;

    function setAuthorities(address[] calldata list, uint256 threshold) external {
        _authorities.threshold = threshold;
        for (uint256 i = 0; i < list.length; i++) {
            _authorities.members[list[i]] = true;
        }
    }

    function domainSeparator(SignatureVerification.Domain memory d) external pure returns (bytes32) {
        return SignatureVerification.domainSeparator(d);
    }

    function digest(bytes32 domainSep, bytes32 structHash) external pure returns (bytes32) {
        return SignatureVerification.digest(domainSep, structHash);
    }

    function recover(bytes32 d, bytes memory signature) external pure returns (address) {
        return SignatureVerification.recover(d, signature);
    }

    function verifySingle(bytes32 d, bytes memory signature, address expected) external pure returns (bool) {
        return SignatureVerification.verifySingle(d, signature, expected);
    }

    function verifyQuorum(
        bytes32 domainSep,
        bytes32 structHash,
        bytes[] calldata signatures
    ) external view returns (bool ok, uint256 count) {
        return SignatureVerification.verifyQuorum(domainSep, structHash, signatures, _authorities);
    }
}

contract SignatureVerificationTest is Test {
    SignatureVerificationHarness internal h;
    address internal alice;
    uint256 internal aliceKey;
    address internal bob;
    uint256 internal bobKey;

    function setUp() public {
        h = new SignatureVerificationHarness();
        (alice, aliceKey) = makeAddrAndKey("alice");
        (bob, bobKey) = makeAddrAndKey("bob");
    }

    function _sign(uint256 key, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, d);
        return abi.encodePacked(r, s, v);
    }

    // ----- domainSeparator --------------------------------------------------

    function test_domainSeparator_matchesEip712Spec() public view {
        SignatureVerification.Domain memory d = SignatureVerification.Domain({
            name: "T3RRA-Test",
            version: "1",
            chainId: block.chainid,
            verifyingContract: address(h)
        });
        bytes32 expected = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("T3RRA-Test")),
            keccak256(bytes("1")),
            block.chainid,
            address(h)
        ));
        assertEq(h.domainSeparator(d), expected);
    }

    function test_domainSeparator_deterministic() public view {
        SignatureVerification.Domain memory d = SignatureVerification.Domain({
            name: "n", version: "v", chainId: 1, verifyingContract: address(0x1)
        });
        assertEq(h.domainSeparator(d), h.domainSeparator(d));
    }

    // ----- digest ------------------------------------------------------------

    function test_digest_matchesEip712Envelope() public view {
        bytes32 sep = bytes32(uint256(0xAA));
        bytes32 sh = bytes32(uint256(0xBB));
        bytes32 expected = keccak256(abi.encodePacked(hex"1901", sep, sh));
        assertEq(h.digest(sep, sh), expected);
    }

    // ----- recover (reverting primitive) ------------------------------------

    function test_recover_validSignatureReturnsSigner() public view {
        bytes32 d = keccak256("msg");
        bytes memory sig = _sign(aliceKey, d);
        assertEq(h.recover(d, sig), alice);
    }

    function test_recover_tooShortReverts() public {
        bytes32 d = keccak256("msg");
        bytes memory bad = hex"dead"; // 2 bytes, not 65
        vm.expectRevert(SignatureVerification.InvalidSignature.selector);
        h.recover(d, bad);
    }

    function test_recover_tooLongReverts() public {
        bytes32 d = keccak256("msg");
        bytes memory bad = new bytes(100);
        vm.expectRevert(SignatureVerification.InvalidSignature.selector);
        h.recover(d, bad);
    }

    // ----- verifySingle (non-reverting primitive) ---------------------------

    function test_verifySingle_validSignatureAndMatchingSignerReturnsTrue() public view {
        bytes32 d = keccak256("hello");
        bytes memory sig = _sign(aliceKey, d);
        assertTrue(h.verifySingle(d, sig, alice));
    }

    function test_verifySingle_validSignatureButWrongSignerReturnsFalse() public view {
        bytes32 d = keccak256("hello");
        bytes memory sig = _sign(aliceKey, d);
        assertFalse(h.verifySingle(d, sig, bob));
    }

    function test_verifySingle_malformedSignatureReturnsFalse() public view {
        bytes32 d = keccak256("hello");
        bytes memory bad = hex"dead";
        assertFalse(h.verifySingle(d, bad, alice));
    }

    // ----- verifyQuorum tail-end coverage -----------------------------------

    function test_verifyQuorum_emptyArrayReturnsFalse() public {
        address[] memory auths = new address[](1);
        auths[0] = alice;
        h.setAuthorities(auths, 1);

        bytes[] memory sigs = new bytes[](0);
        (bool ok, uint256 count) = h.verifyQuorum(bytes32(uint256(1)), bytes32(uint256(2)), sigs);
        assertFalse(ok);
        assertEq(count, 0);
    }

    function test_verifyQuorum_malformedSignatureSilentlySkipped() public {
        address[] memory auths = new address[](1);
        auths[0] = alice;
        h.setAuthorities(auths, 1);

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = hex"00"; // malformed
        (bool ok, uint256 count) = h.verifyQuorum(bytes32(uint256(1)), bytes32(uint256(2)), sigs);
        assertFalse(ok);
        assertEq(count, 0);
    }
}
