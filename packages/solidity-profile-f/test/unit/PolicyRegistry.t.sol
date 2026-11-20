// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// PolicyRegistry unit tests.
// Source: 07-profile-f.md (PolicyRegistry surface), L3RS-1 v1.0.0 §5 (governance
//         quorum), Whitepaper v3.3 (L3RS-1 governance-and-amendment process),
//         the project's scope discipline (PolicyRegistry is one of four Phase One
//         contracts). The registry binds a policyId to the current
//         ComplianceModule and records every amendment as a new version.
//
// Since step 5 stage 0 all governance signatures are real ECDSA signatures
// produced via vm.sign against the EIP-712 digest built from each action's
// typehash. DESIGN.md §8.2 is the design of record.

import {Test} from "forge-std/Test.sol";
import {PolicyRegistry} from "../../src/PolicyRegistry.sol";
import {ComplianceModule} from "../../src/ComplianceModule.sol";

contract PolicyRegistryTest is Test {
    PolicyRegistry internal registry;
    ComplianceModule internal c1;
    ComplianceModule internal c2;
    ComplianceModule internal c3;

    address internal issuer;
    uint256 internal issuerKey;
    address internal outsider;
    uint256 internal outsiderKey;
    address internal gov1;
    uint256 internal gov1Key;
    address internal gov2;
    uint256 internal gov2Key;
    address internal gov3;
    uint256 internal gov3Key;

    address[] internal authorities;

    bytes32 internal constant POLICY_ID = bytes32("L3RS-1/POLICY/CRE-MANDATE-001");

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        (outsider, outsiderKey) = makeAddrAndKey("outsider");
        (gov1, gov1Key) = makeAddrAndKey("gov1");
        (gov2, gov2Key) = makeAddrAndKey("gov2");
        (gov3, gov3Key) = makeAddrAndKey("gov3");

        authorities.push(gov1);
        authorities.push(gov2);
        authorities.push(gov3);

        vm.startPrank(issuer);
        registry = new PolicyRegistry(authorities);
        c1 = new ComplianceModule(authorities);
        c2 = new ComplianceModule(authorities);
        c3 = new ComplianceModule(authorities);
        vm.stopPrank();
    }

    // ----- signature helpers ---------------------------------------------------

    function _signDigest(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _eip712(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", registry.DOMAIN_SEPARATOR(), structHash));
    }

    function _amendDigest(bytes32 policyId, address newModule, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        return _eip712(keccak256(abi.encode(
            registry.AMEND_TYPEHASH(), address(registry), policyId, newModule, nonce, deadline
        )));
    }

    function _retireDigest(bytes32 policyId, uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        return _eip712(keccak256(abi.encode(
            registry.RETIRE_TYPEHASH(), address(registry), policyId, nonce, deadline
        )));
    }

    function _twoGovSigs(bytes32 digest) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        sigs[0] = _signDigest(gov1Key, digest);
        sigs[1] = _signDigest(gov2Key, digest);
    }

    function _oneGovSig(bytes32 digest) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](1);
        sigs[0] = _signDigest(gov1Key, digest);
    }

    // ----- registration --------------------------------------------------------

    function test_register_bindsModuleAndHash() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        PolicyRegistry.Binding memory current = registry.getCurrent(POLICY_ID);
        assertEq(current.complianceModule, address(c1), "register: wrong module");
        assertEq(current.canonicalHash, c1.complianceHash(), "register: hash not captured");
        assertEq(current.version, 1, "register: initial version not 1");
        assertEq(current.retiredAt, 0, "register: initial binding is retired");
        assertGt(current.activatedAt, 0, "register: activatedAt not set");
    }

    function test_register_onlyOwner() public {
        vm.prank(outsider);
        vm.expectRevert();
        registry.register(POLICY_ID, address(c1));
    }

    function test_register_duplicatePolicyIdReverts() public {
        vm.startPrank(issuer);
        registry.register(POLICY_ID, address(c1));
        vm.expectRevert();
        registry.register(POLICY_ID, address(c2));
        vm.stopPrank();
    }

    function test_register_zeroModuleReverts() public {
        vm.prank(issuer);
        vm.expectRevert();
        registry.register(POLICY_ID, address(0));
    }

    // ----- amendment -----------------------------------------------------------

    function test_amend_requiresQuorum() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        bytes[] memory sigs = _oneGovSig(digest);

        vm.expectRevert();
        registry.amend(POLICY_ID, address(c2), nonce, deadline, sigs);
    }

    function test_amend_createsNewVersionAndRetiresOld() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        bytes[] memory sigs = _twoGovSigs(digest);

        registry.amend(POLICY_ID, address(c2), nonce, deadline, sigs);

        assertEq(registry.versionCount(POLICY_ID), 2, "amend: version count not incremented");

        PolicyRegistry.Binding memory current = registry.getCurrent(POLICY_ID);
        assertEq(current.complianceModule, address(c2), "amend: current module not updated");
        assertEq(current.version, 2, "amend: new binding version not 2");
        assertEq(current.canonicalHash, c2.complianceHash(), "amend: new hash not captured");
        assertEq(current.retiredAt, 0, "amend: new binding is retired");

        PolicyRegistry.Binding memory prior = registry.getBinding(POLICY_ID, 1);
        assertEq(prior.complianceModule, address(c1), "amend: prior module not preserved");
        assertGt(prior.retiredAt, 0, "amend: prior binding not marked retired");
    }

    function test_amend_nonAuthorityCallerReverts() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        // Sign with outsider (not in authorized set) — verifyQuorum skips, count=0<2.
        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _signDigest(outsiderKey, digest);
        sigs[1] = _signDigest(outsiderKey, digest);

        vm.expectRevert();
        registry.amend(POLICY_ID, address(c2), nonce, deadline, sigs);
    }

    function test_amend_unknownPolicyReverts() public {
        bytes32 unknown = bytes32("UNREGISTERED");
        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(unknown, address(c2), nonce, deadline);
        bytes[] memory sigs = _twoGovSigs(digest);

        vm.expectRevert();
        registry.amend(unknown, address(c2), nonce, deadline, sigs);
    }

    function test_amend_duplicateSignatureReverts() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        // Both sigs from same signer — verifyQuorum dedups by address, count=1<2.
        bytes memory sig = _signDigest(gov1Key, digest);
        bytes[] memory duplicated = new bytes[](2);
        duplicated[0] = sig;
        duplicated[1] = sig;

        vm.expectRevert();
        registry.amend(POLICY_ID, address(c2), nonce, deadline, duplicated);
    }

    function test_amend_threeVersionsChainCorrectly() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d1 = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        registry.amend(POLICY_ID, address(c2), nonce, deadline, _twoGovSigs(d1));

        nonce = registry.governanceNonce();
        bytes32 d2 = _amendDigest(POLICY_ID, address(c3), nonce, deadline);
        registry.amend(POLICY_ID, address(c3), nonce, deadline, _twoGovSigs(d2));

        assertEq(registry.versionCount(POLICY_ID), 3, "three-version chain: count");

        PolicyRegistry.Binding memory v1 = registry.getBinding(POLICY_ID, 1);
        PolicyRegistry.Binding memory v2 = registry.getBinding(POLICY_ID, 2);
        PolicyRegistry.Binding memory v3 = registry.getBinding(POLICY_ID, 3);

        assertEq(v1.complianceModule, address(c1));
        assertEq(v2.complianceModule, address(c2));
        assertEq(v3.complianceModule, address(c3));
        assertGt(v1.retiredAt, 0, "v1 not retired");
        assertGt(v2.retiredAt, 0, "v2 not retired");
        assertEq(v3.retiredAt, 0, "v3 retired incorrectly");
    }

    // ----- retirement ----------------------------------------------------------

    function test_retire_requiresQuorum() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _retireDigest(POLICY_ID, nonce, deadline);
        bytes[] memory sigs = _oneGovSig(digest);

        vm.expectRevert();
        registry.retire(POLICY_ID, nonce, deadline, sigs);
    }

    function test_retire_marksRetiredAndBlocksFurtherAmend() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 rDigest = _retireDigest(POLICY_ID, nonce, deadline);
        registry.retire(POLICY_ID, nonce, deadline, _twoGovSigs(rDigest));

        PolicyRegistry.Binding memory current = registry.getCurrent(POLICY_ID);
        assertGt(current.retiredAt, 0, "retire: not marked retired");
        assertEq(registry.isActive(POLICY_ID), false, "retire: isActive not false");

        // Further amendments on a retired policy should revert.
        nonce = registry.governanceNonce();
        bytes32 aDigest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        vm.expectRevert();
        registry.amend(POLICY_ID, address(c2), nonce, deadline, _twoGovSigs(aDigest));
    }

    // ----- history access ------------------------------------------------------

    function test_getHistory_returnsAllVersions() public {
        vm.startPrank(issuer);
        registry.register(POLICY_ID, address(c1));
        vm.stopPrank();

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        registry.amend(POLICY_ID, address(c2), nonce, deadline, _twoGovSigs(digest));

        PolicyRegistry.Binding[] memory history = registry.getHistory(POLICY_ID);
        assertEq(history.length, 2, "history: wrong length");
        assertEq(history[0].complianceModule, address(c1), "history[0] wrong");
        assertEq(history[1].complianceModule, address(c2), "history[1] wrong");
    }

    function test_getBinding_outOfRangeReverts() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        vm.expectRevert();
        registry.getBinding(POLICY_ID, 99);
    }

    // ----- registry root -------------------------------------------------------

    function test_registryRoot_isStableBetweenAmendments() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        bytes32 rootA = registry.registryRoot();
        bytes32 rootB = registry.registryRoot();
        assertEq(rootA, rootB, "registryRoot: non-deterministic reads");
    }

    function test_registryRoot_changesOnAmend() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        bytes32 rootBefore = registry.registryRoot();

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        registry.amend(POLICY_ID, address(c2), nonce, deadline, _twoGovSigs(digest));

        bytes32 rootAfter = registry.registryRoot();
        assertTrue(rootBefore != rootAfter, "registryRoot: unchanged after amend");
    }

    function test_registryRoot_changesOnRegistration() public {
        bytes32 rootBefore = registry.registryRoot();

        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));

        bytes32 rootAfter = registry.registryRoot();
        assertTrue(rootBefore != rootAfter, "registryRoot: unchanged after register");
    }

    // ----- current-hash accessor used by the bridge consumer ------------------

    function test_currentHash_tracksAmendments() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));
        assertEq(registry.currentHash(POLICY_ID), c1.complianceHash());

        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        registry.amend(POLICY_ID, address(c2), nonce, deadline, _twoGovSigs(digest));
        assertEq(registry.currentHash(POLICY_ID), c2.complianceHash());
    }

    function test_currentHash_unknownPolicyReverts() public {
        vm.expectRevert();
        registry.currentHash(bytes32("UNREGISTERED"));
    }

    // ----- 6B: view accessor coverage ----------------------------------------

    function test_6B_view_authorities() public view {
        address[] memory list = registry.authorities();
        assertEq(list.length, 3);
        assertEq(list[0], gov1);
    }

    function test_6B_view_policyIdsEmptyInitially() public view {
        bytes32[] memory ids = registry.policyIds();
        assertEq(ids.length, 0);
    }

    function test_6B_view_policyIdsAfterRegistrations() public {
        vm.startPrank(issuer);
        registry.register(POLICY_ID, address(c1));
        registry.register(bytes32("POLICY-2"), address(c2));
        vm.stopPrank();

        bytes32[] memory ids = registry.policyIds();
        assertEq(ids.length, 2);
        assertEq(ids[0], POLICY_ID);
        assertEq(ids[1], bytes32("POLICY-2"));
    }

    function test_6B_view_isActiveForUnregisteredReturnsFalse() public view {
        assertFalse(registry.isActive(bytes32("NOT-REGISTERED")));
    }

    function test_6B_view_getCurrent_unknownPolicyReverts() public {
        vm.expectRevert();
        registry.getCurrent(bytes32("UNKNOWN"));
    }

    function test_6B_view_getHistory_unknownPolicyReverts() public {
        vm.expectRevert();
        registry.getHistory(bytes32("UNKNOWN"));
    }

    function test_6B_view_versionCount_unknownPolicyReverts() public {
        vm.expectRevert();
        registry.versionCount(bytes32("UNKNOWN"));
    }

    function test_6B_view_getBinding_versionZeroReverts() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));
        vm.expectRevert();
        registry.getBinding(POLICY_ID, 0);
    }

    // ----- 6B: constructor branch coverage -----------------------------------

    function test_6B_constructor_rejectsTooFewAuthorities() public {
        address[] memory two = new address[](2);
        two[0] = gov1; two[1] = gov2;
        vm.expectRevert(bytes("PolicyRegistry: need >=3 authorities"));
        new PolicyRegistry(two);
    }

    function test_6B_constructor_rejectsZeroAuthority() public {
        address[] memory withZero = new address[](3);
        withZero[0] = gov1; withZero[1] = address(0); withZero[2] = gov3;
        vm.expectRevert();
        new PolicyRegistry(withZero);
    }

    function test_6B_constructor_rejectsDuplicateAuthority() public {
        address[] memory dup = new address[](3);
        dup[0] = gov1; dup[1] = gov2; dup[2] = gov1;
        vm.expectRevert();
        new PolicyRegistry(dup);
    }

    // ----- 6B: amend / retire branch coverage --------------------------------

    function test_6B_amend_rejectsInvalidNonce() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));
        uint256 badNonce = registry.governanceNonce() + 7;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), badNonce, deadline);
        vm.expectRevert();
        registry.amend(POLICY_ID, address(c2), badNonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_amend_rejectsExpiredDeadline() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));
        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp - 1;
        bytes32 digest = _amendDigest(POLICY_ID, address(c2), nonce, deadline);
        vm.expectRevert();
        registry.amend(POLICY_ID, address(c2), nonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_amend_rejectsZeroNewModule() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));
        uint256 nonce = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _amendDigest(POLICY_ID, address(0), nonce, deadline);
        vm.expectRevert();
        registry.amend(POLICY_ID, address(0), nonce, deadline, _twoGovSigs(digest));
    }

    function test_6B_retire_rejectsRetiredPolicy() public {
        vm.prank(issuer);
        registry.register(POLICY_ID, address(c1));
        // First retire.
        uint256 n = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _retireDigest(POLICY_ID, n, deadline);
        registry.retire(POLICY_ID, n, deadline, _twoGovSigs(digest));
        // Second retire of same policy should revert.
        uint256 n2 = registry.governanceNonce();
        bytes32 d2 = _retireDigest(POLICY_ID, n2, deadline);
        vm.expectRevert();
        registry.retire(POLICY_ID, n2, deadline, _twoGovSigs(d2));
    }

    function test_6B_retire_rejectsUnknownPolicy() public {
        uint256 n = registry.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _retireDigest(bytes32("UNKNOWN"), n, deadline);
        vm.expectRevert();
        registry.retire(bytes32("UNKNOWN"), n, deadline, _twoGovSigs(digest));
    }

    function test_6B_register_rejectsNonOwner() public {
        vm.prank(outsider);
        vm.expectRevert();
        registry.register(POLICY_ID, address(c1));
    }
}
