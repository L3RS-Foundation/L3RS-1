// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Direct unit tests for ComplianceModule. Focuses on view accessors (not
// transitively covered) and revert-path branch coverage. Source: DESIGN.md §12
// 6A priority 2 and priority 5.

import {Test} from "forge-std/Test.sol";
import {ComplianceModule} from "../../src/ComplianceModule.sol";
import {IComplianceModuleF} from "../../src/interfaces/IComplianceModuleF.sol";
import {ReasonCodes} from "../../src/libraries/ReasonCodes.sol";

contract ComplianceModuleTest is Test {
    ComplianceModule internal compliance;

    address internal issuer;
    uint256 internal issuerKey;
    address internal gov1;
    uint256 internal gov1Key;
    address internal gov2;
    uint256 internal gov2Key;
    address internal gov3;
    uint256 internal gov3Key;
    address internal outsider;

    address[] internal authorities;

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        (gov1, gov1Key) = makeAddrAndKey("gov1");
        (gov2, gov2Key) = makeAddrAndKey("gov2");
        (gov3, gov3Key) = makeAddrAndKey("gov3");
        outsider = makeAddr("outsider");

        authorities.push(gov1);
        authorities.push(gov2);
        authorities.push(gov3);

        vm.prank(issuer);
        compliance = new ComplianceModule(authorities);
    }

    function _sign(uint256 key, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, d);
        return abi.encodePacked(r, s, v);
    }

    // ----- view accessor coverage --------------------------------------------

    function test_view_version() public view {
        assertEq(compliance.version(), 1);
    }

    function test_view_authorities() public view {
        address[] memory list = compliance.authorities();
        assertEq(list.length, 3);
        assertEq(list[0], gov1);
        assertEq(list[1], gov2);
        assertEq(list[2], gov3);
    }

    function test_view_getRulesEmptyInitially() public view {
        IComplianceModuleF.Rule[] memory rules = compliance.getRules();
        assertEq(rules.length, 0);
    }

    function test_view_getRulesReflectsMutations() public {
        vm.prank(issuer);
        compliance.addSanctionedAddress(address(0xBEEF));
        vm.prank(issuer);
        compliance.allowJurisdictionPair(bytes2("GB"), bytes2("US"));

        IComplianceModuleF.Rule[] memory rules = compliance.getRules();
        assertEq(rules.length, 2);
        assertEq(uint8(rules[0].ruleType), uint8(IComplianceModuleF.RuleType.SANCTIONS_SCREENING));
        assertEq(uint8(rules[1].ruleType), uint8(IComplianceModuleF.RuleType.GEOGRAPHIC_RESTRICTION));
        assertEq(uint8(rules[0].action), uint8(IComplianceModuleF.EnforcementAction.REJECT));
    }

    function test_view_observedRevertCountAlwaysZero() public view {
        assertEq(compliance.observedRevertCount(), 0);
    }

    function test_view_serializationAndHashChangeCountsAreEqual() public view {
        // After constructor both are 1 (initial _recordHashChange).
        assertEq(compliance.serializationChangeCount(), compliance.hashChangeCount());
    }

    function test_view_changeCountsAdvanceOnMutation() public {
        uint256 sBefore = compliance.serializationChangeCount();
        uint256 hBefore = compliance.hashChangeCount();
        vm.prank(issuer);
        compliance.addSanctionedAddress(address(0xBEEF));
        assertEq(compliance.serializationChangeCount(), sBefore + 1);
        assertEq(compliance.hashChangeCount(), hBefore + 1);
    }

    // ----- constructor revert branches ---------------------------------------

    function test_constructor_needsThreeAuthorities() public {
        address[] memory two = new address[](2);
        two[0] = gov1;
        two[1] = gov2;
        vm.expectRevert(bytes("ComplianceModule: need >=3 authorities"));
        new ComplianceModule(two);
    }

    function test_constructor_rejectsZeroAuthority() public {
        address[] memory bad = new address[](3);
        bad[0] = gov1;
        bad[1] = address(0);
        bad[2] = gov3;
        vm.expectRevert(bytes("ComplianceModule: zero authority"));
        new ComplianceModule(bad);
    }

    function test_constructor_rejectsDuplicateAuthority() public {
        address[] memory dup = new address[](3);
        dup[0] = gov1;
        dup[1] = gov2;
        dup[2] = gov1; // duplicate
        vm.expectRevert(bytes("ComplianceModule: duplicate authority"));
        new ComplianceModule(dup);
    }

    // ----- addSanctionedAddress branches -------------------------------------

    function test_addSanctionedAddress_revertsForNonOwner() public {
        vm.prank(outsider);
        vm.expectRevert(bytes("ComplianceModule: not owner"));
        compliance.addSanctionedAddress(address(0xBEEF));
    }

    function test_addSanctionedAddress_rejectsZeroAddress() public {
        vm.prank(issuer);
        vm.expectRevert(bytes("ComplianceModule: zero address"));
        compliance.addSanctionedAddress(address(0));
    }

    function test_addSanctionedAddress_rejectsDuplicate() public {
        vm.startPrank(issuer);
        compliance.addSanctionedAddress(address(0xBEEF));
        vm.expectRevert(bytes("ComplianceModule: already sanctioned"));
        compliance.addSanctionedAddress(address(0xBEEF));
        vm.stopPrank();
    }

    // ----- allowJurisdictionPair branches ------------------------------------

    function test_allowJurisdictionPair_revertsForNonOwner() public {
        vm.prank(outsider);
        vm.expectRevert();
        compliance.allowJurisdictionPair(bytes2("GB"), bytes2("US"));
    }

    function test_allowJurisdictionPair_rejectsZeroSender() public {
        vm.prank(issuer);
        vm.expectRevert(bytes("ComplianceModule: zero sender jurisdiction"));
        compliance.allowJurisdictionPair(bytes2(0), bytes2("US"));
    }

    function test_allowJurisdictionPair_rejectsZeroReceiver() public {
        vm.prank(issuer);
        vm.expectRevert(bytes("ComplianceModule: zero receiver jurisdiction"));
        compliance.allowJurisdictionPair(bytes2("GB"), bytes2(0));
    }

    function test_allowJurisdictionPair_rejectsDuplicatePair() public {
        vm.startPrank(issuer);
        compliance.allowJurisdictionPair(bytes2("GB"), bytes2("US"));
        vm.expectRevert(bytes("ComplianceModule: pair already allowed"));
        compliance.allowJurisdictionPair(bytes2("GB"), bytes2("US"));
        vm.stopPrank();
    }

    // ----- bumpVersion branches ----------------------------------------------

    function _bumpVersionDigest(uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            compliance.BUMP_VERSION_TYPEHASH(), address(compliance), nonce, deadline
        ));
        return keccak256(abi.encodePacked(hex"1901", compliance.DOMAIN_SEPARATOR(), structHash));
    }

    function test_bumpVersion_revertsOnInvalidNonce() public {
        uint256 wrongNonce = compliance.governanceNonce() + 5;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = _bumpVersionDigest(wrongNonce, deadline);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gov1Key, d);
        sigs[1] = _sign(gov2Key, d);
        vm.expectRevert(ComplianceModule.InvalidNonce.selector);
        compliance.bumpVersion(wrongNonce, deadline, sigs);
    }

    function test_bumpVersion_revertsOnExpiredDeadline() public {
        uint256 nonce = compliance.governanceNonce();
        uint256 deadline = block.timestamp - 1;
        bytes32 d = _bumpVersionDigest(nonce, deadline);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gov1Key, d);
        sigs[1] = _sign(gov2Key, d);
        vm.expectRevert(ComplianceModule.Expired.selector);
        compliance.bumpVersion(nonce, deadline, sigs);
    }

    function test_bumpVersion_revertsOnInsufficientSignatures() public {
        uint256 nonce = compliance.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = _bumpVersionDigest(nonce, deadline);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(gov1Key, d);
        vm.expectRevert(ComplianceModule.InsufficientSignatures.selector);
        compliance.bumpVersion(nonce, deadline, sigs);
    }

    // ----- removeSanctionedAddress branches (external scoping review) ---

    function _removeSanctionedDigest(address who, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(compliance.REMOVE_SANCTIONED_TYPEHASH(), address(compliance), who, nonce, deadline)
        );
        return keccak256(abi.encodePacked(hex"1901", compliance.DOMAIN_SEPARATOR(), structHash));
    }

    function _removeSanctionedTwoSigs(address who) internal view returns (uint256, uint256, bytes[] memory) {
        uint256 nonce = compliance.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = _removeSanctionedDigest(who, nonce, deadline);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gov1Key, d);
        sigs[1] = _sign(gov2Key, d);
        return (nonce, deadline, sigs);
    }

    /// @notice Happy path: quorum removes a sanctioned address; mapping and
    ///         canonical-list both reflect the removal; hash changes; event
    ///         emitted; governance nonce advances.
    function test_removeSanctionedAddress_happyPath() public {
        address target = address(0xCAFE);
        vm.prank(issuer);
        compliance.addSanctionedAddress(target);
        assertTrue(compliance.complianceHash() != bytes32(0));
        bytes32 hashBefore = compliance.complianceHash();
        uint256 nonceBefore = compliance.governanceNonce();

        (uint256 n, uint256 dl, bytes[] memory sigs) = _removeSanctionedTwoSigs(target);
        vm.expectEmit(true, false, false, false);
        emit SanctionedAddressRemoved(target);
        compliance.removeSanctionedAddress(target, n, dl, sigs);

        // Mapping flip observable via evaluate's SANCTIONS reason absence.
        bytes memory fullCtx = abi.encode(
            bytes32("L3RS-1/CTX/v1"), address(this), target, address(0xBEEF),
            uint256(1), bytes2("GB"), bytes2("GB"),
            uint64(block.timestamp), uint256(0), bytes("")
        );
        vm.prank(issuer);
        compliance.allowJurisdictionPair(bytes2("GB"), bytes2("GB"));
        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), target, address(0xBEEF), 1, fullCtx
        );
        assertTrue(allow, "no longer sanctioned");
        assertEq(reason, ReasonCodes.NONE);

        // Hash changed; governance nonce advanced.
        assertTrue(compliance.complianceHash() != hashBefore, "hash changed on removal");
        assertEq(compliance.governanceNonce(), nonceBefore + 1, "gov nonce advanced");
    }

    /// @notice Minority signer: single-sig attempt reverts InsufficientSignatures.
    function test_removeSanctionedAddress_minoritySignerRejects() public {
        address target = address(0xCAFE);
        vm.prank(issuer);
        compliance.addSanctionedAddress(target);

        uint256 nonce = compliance.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = _removeSanctionedDigest(target, nonce, deadline);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(gov1Key, d);
        vm.expectRevert(ComplianceModule.InsufficientSignatures.selector);
        compliance.removeSanctionedAddress(target, nonce, deadline, sigs);
    }

    /// @notice Non-authority signer: signatures by non-members contribute zero
    ///         to the distinct count, so a 2-of-"authority-plus-outsider" set
    ///         fails the quorum check.
    function test_removeSanctionedAddress_nonAuthorityRejects() public {
        address target = address(0xCAFE);
        vm.prank(issuer);
        compliance.addSanctionedAddress(target);

        // Use a key that does not correspond to any registered authority.
        (, uint256 outsiderKey) = makeAddrAndKey("outsider-signer");

        uint256 nonce = compliance.governanceNonce();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = _removeSanctionedDigest(target, nonce, deadline);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gov1Key, d);
        sigs[1] = _sign(outsiderKey, d);
        vm.expectRevert(ComplianceModule.InsufficientSignatures.selector);
        compliance.removeSanctionedAddress(target, nonce, deadline, sigs);
    }

    /// @notice Removing an address that was never sanctioned reverts
    ///         NotSanctioned (quorum passes, precondition fails).
    function test_removeSanctionedAddress_notSanctionedReverts() public {
        address target = address(0xBEEF);
        (uint256 n, uint256 dl, bytes[] memory sigs) = _removeSanctionedTwoSigs(target);
        vm.expectRevert(ComplianceModule.NotSanctioned.selector);
        compliance.removeSanctionedAddress(target, n, dl, sigs);
    }

    /// @notice Invalid nonce path: quorum check does not run before nonce
    ///         validation, so the revert reason is InvalidNonce not
    ///         InsufficientSignatures.
    function test_removeSanctionedAddress_invalidNonceReverts() public {
        address target = address(0xCAFE);
        vm.prank(issuer);
        compliance.addSanctionedAddress(target);
        uint256 wrongNonce = compliance.governanceNonce() + 7;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 d = _removeSanctionedDigest(target, wrongNonce, deadline);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gov1Key, d);
        sigs[1] = _sign(gov2Key, d);
        vm.expectRevert(ComplianceModule.InvalidNonce.selector);
        compliance.removeSanctionedAddress(target, wrongNonce, deadline, sigs);
    }

    /// @notice Full lifecycle: add → remove → re-add. The canonical list
    ///         length bounces 0 → 1 → 0 → 1; hash changes each hop. Serves
    ///         as the invariant-style check against the swap-and-pop removal
    ///         logic.
    function test_removeSanctionedAddress_fullLifecycle() public {
        address target = address(0xCAFE);

        bytes32 h0 = compliance.complianceHash();

        vm.prank(issuer);
        compliance.addSanctionedAddress(target);
        bytes32 h1 = compliance.complianceHash();
        assertTrue(h1 != h0, "hash changes on add");

        (uint256 n, uint256 dl, bytes[] memory sigs) = _removeSanctionedTwoSigs(target);
        compliance.removeSanctionedAddress(target, n, dl, sigs);
        bytes32 h2 = compliance.complianceHash();
        assertTrue(h2 != h1, "hash changes on remove");
        // After removal the set is empty, matching the pre-add hash.
        assertEq(h2, h0, "hash returns to pre-add value");

        vm.prank(issuer);
        compliance.addSanctionedAddress(target);
        bytes32 h3 = compliance.complianceHash();
        assertEq(h3, h1, "re-add restores pre-remove hash");
    }

    // Local event declaration mirror so `vm.expectEmit` resolves the signature.
    event SanctionedAddressRemoved(address indexed who);

    // ----- evaluate: total-function contract at boundary conditions ---------

    function test_evaluate_shortContextSkipsGeographicRule() public {
        vm.prank(issuer);
        compliance.addSanctionedAddress(address(0xBEEF));

        bytes memory shortCtx = abi.encode(bytes32("SHORT"));
        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 1, shortCtx
        );
        // Neither party sanctioned; geographic does not run; allow.
        assertTrue(allow);
        assertEq(reason, ReasonCodes.NONE);
    }

    function test_evaluate_emptyContextNeverReverts() public view {
        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 0, ""
        );
        assertTrue(allow);
        assertEq(reason, ReasonCodes.NONE);
    }

    function test_evaluate_sanctionedSenderReturnsSanctionsReason() public {
        vm.prank(issuer);
        compliance.addSanctionedAddress(address(0xAAAA));
        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 1, ""
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.SANCTIONS);
    }

    /// @notice 6B: exercise the GEOGRAPHIC reject branch. Build a full-length
    ///         transfer context with jurisdictions that have NOT been allowed
    ///         and expect the geographic rule to reject.
    function test_evaluate_unallowedJurisdictionPairReturnsGeographicReason() public view {
        // Build a 10-slot context per BaseTest.encodeContext layout. Sender
        // jurisdiction at slot 5, receiver at slot 6, both as bytes2 at the
        // high bits of a 32-byte slot.
        bytes memory ctx = abi.encode(
            bytes32("L3RS-1/CTX/v1"),  // slot 0: tag
            address(this),              // slot 1: assetRef
            address(0xAAAA),            // slot 2: sender
            address(0xBBBB),            // slot 3: receiver
            uint256(100),               // slot 4: amount
            bytes2("GB"),               // slot 5: sender jurisdiction (not allowed)
            bytes2("US"),               // slot 6: receiver jurisdiction
            uint64(block.timestamp),    // slot 7: timestamp
            uint256(0),                 // slot 8: nonce
            bytes("")                   // dynamic: payload
        );
        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 100, ctx
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.GEOGRAPHIC);
    }

    // ----- hashOf and canonicalHashDomain direct reads ----------------------

    function test_canonicalHashDomain_returnsSpecString() public view {
        assertEq(compliance.canonicalHashDomain(), bytes("T3RRA-POLICY-HASH-v1"));
    }

    function test_hashOf_matchesInternalHash() public view {
        bytes memory ser = compliance.canonicalSerialization();
        bytes32 derived = compliance.hashOf(ser);
        assertEq(derived, compliance.complianceHash());
    }

    // ========================================================================
    // 6D — seven new L3RS-1 §4.4 rule types
    // ========================================================================

    // Helper: construct a full-length transfer context (10 slots + empty bytes).
    function _ctxFull(address sender, address receiver, uint256 amount, bytes2 sj, bytes2 rj)
        internal view returns (bytes memory)
    {
        return abi.encode(
            bytes32("L3RS-1/CTX/v1"),
            address(this),
            sender,
            receiver,
            amount,
            sj,
            rj,
            uint64(block.timestamp),
            uint256(0),
            bytes("")
        );
    }

    // ----- TRANSFER_ELIGIBILITY ---------------------------------------------

    function test_6D_transferEligibility_configurationRoundtrip() public {
        assertFalse(compliance.transferIneligible(address(0xAAAA)));
        vm.prank(issuer);
        compliance.setTransferIneligible(address(0xAAAA), true);
        assertTrue(compliance.transferIneligible(address(0xAAAA)));
    }

    function test_6D_transferEligibility_rejectsIneligibleSender() public {
        vm.prank(issuer);
        compliance.setTransferIneligible(address(0xAAAA), true);

        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 1, ""
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.TRANSFER_INELIGIBLE);
    }

    function test_6D_transferEligibility_rejectsIneligibleReceiver() public {
        vm.prank(issuer);
        compliance.setTransferIneligible(address(0xBBBB), true);

        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 1, ""
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.TRANSFER_INELIGIBLE);
    }

    function test_6D_transferEligibility_rejectsZeroAddress() public {
        vm.prank(issuer);
        vm.expectRevert();
        compliance.setTransferIneligible(address(0), true);
    }

    function test_6D_transferEligibility_rejectsNonOwner() public {
        vm.prank(outsider);
        vm.expectRevert();
        compliance.setTransferIneligible(address(0xAAAA), true);
    }

    // ----- TRANSACTION_THRESHOLD --------------------------------------------

    function test_6D_transactionThreshold_rejectsAmountAboveLimit() public {
        vm.prank(issuer);
        compliance.setTransactionThreshold(1_000);

        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 1_001, ""
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.THRESHOLD);
    }

    function test_6D_transactionThreshold_allowsAtLimit() public {
        vm.prank(issuer);
        compliance.setTransactionThreshold(1_000);
        (bool allow, ) = compliance.evaluate(address(this), address(0xAAAA), address(0xBBBB), 1_000, "");
        assertTrue(allow);
    }

    function test_6D_transactionThreshold_disabledWhenZero() public {
        (bool allow, ) = compliance.evaluate(address(this), address(0xAAAA), address(0xBBBB), 10_000_000, "");
        assertTrue(allow);
    }

    // ----- AML_TRIGGER ------------------------------------------------------

    function test_6D_amlTrigger_rejectsAtOrAboveThreshold() public {
        vm.prank(issuer);
        compliance.setAmlThreshold(10_000);

        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 10_000, ""
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.AML);
    }

    function test_6D_amlTrigger_allowsBelowThreshold() public {
        vm.prank(issuer);
        compliance.setAmlThreshold(10_000);
        (bool allow, ) = compliance.evaluate(address(this), address(0xAAAA), address(0xBBBB), 9_999, "");
        assertTrue(allow);
    }

    // ----- MARKET_RESTRICTION -----------------------------------------------

    function test_6D_marketRestriction_rejectsOutsideHours() public {
        // Open hours: 09:00-17:00 UTC. Warp to midnight UTC (hour 0).
        vm.warp(1_700_000_000); // arbitrary; map to any hour
        // Force block.timestamp to land at hour 3 (03:00 UTC) — outside 09-17.
        uint256 atHour3 = (block.timestamp / 86400) * 86400 + 3 * 3600;
        vm.warp(atHour3);

        vm.prank(issuer);
        compliance.setMarketHours(9, 17);

        (bool allow, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 1, ""
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.MARKET);
    }

    function test_6D_marketRestriction_allowsInsideHours() public {
        uint256 atHour12 = (block.timestamp / 86400) * 86400 + 12 * 3600;
        vm.warp(atHour12);

        vm.prank(issuer);
        compliance.setMarketHours(9, 17);

        (bool allow, ) = compliance.evaluate(address(this), address(0xAAAA), address(0xBBBB), 1, "");
        assertTrue(allow);
    }

    function test_6D_marketRestriction_startEqualsEndDisables() public {
        vm.prank(issuer);
        compliance.setMarketHours(0, 0);
        (bool allow, ) = compliance.evaluate(address(this), address(0xAAAA), address(0xBBBB), 1, "");
        assertTrue(allow);
    }

    function test_6D_marketRestriction_revertsOnInvalidRange() public {
        vm.prank(issuer);
        vm.expectRevert();
        compliance.setMarketHours(18, 9);
    }

    // ----- INVESTOR_CLASSIFICATION (extended) -------------------------------

    function test_6D_investorClassification_rejectsReceiverBelowMinTier() public {
        vm.prank(issuer);
        compliance.setMinInvestorTier(2);

        (bool allow, bytes32 reason) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            1,      // receiverTier = 1, below minimum 2
            0,
            bytes32("TRANSFER")
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.INVESTOR_CLASS);
    }

    function test_6D_investorClassification_allowsAtMinTier() public {
        vm.prank(issuer);
        compliance.setMinInvestorTier(2);

        (bool allow, ) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            2, 0, bytes32("TRANSFER")
        );
        assertTrue(allow);
    }

    function test_6D_investorClassification_disabledWhenZero() public {
        (bool allow, ) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            0, 0, bytes32("TRANSFER")
        );
        assertTrue(allow);
    }

    // ----- HOLDING_PERIOD (extended) ----------------------------------------

    function test_6D_holdingPeriod_rejectsBeforePeriodElapsed() public {
        vm.prank(issuer);
        compliance.setMinHoldingPeriod(180 days);

        uint256 acquiredAt = block.timestamp;
        vm.warp(acquiredAt + 60 days); // only 60 days held

        (bool allow, bytes32 reason) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            3, acquiredAt, bytes32("TRANSFER")
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.HOLDING_PERIOD);
    }

    function test_6D_holdingPeriod_allowsAfterPeriodElapsed() public {
        vm.prank(issuer);
        compliance.setMinHoldingPeriod(180 days);

        uint256 acquiredAt = block.timestamp;
        vm.warp(acquiredAt + 181 days);

        (bool allow, ) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            3, acquiredAt, bytes32("TRANSFER")
        );
        assertTrue(allow);
    }

    function test_6D_holdingPeriod_disabledWhenSenderFirstReceivedIsZero() public {
        vm.prank(issuer);
        compliance.setMinHoldingPeriod(180 days);
        // senderFirstReceivedAt = 0 → rule skipped (no data to evaluate).
        (bool allow, ) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            3, 0, bytes32("TRANSFER")
        );
        assertTrue(allow);
    }

    // ----- REDEMPTION_ELIGIBILITY (extended) --------------------------------

    function test_6D_redemptionEligibility_rejectsOnIneligibleHolder() public {
        vm.prank(issuer);
        compliance.setRedemptionIneligible(address(0xAAAA), true);

        (bool allow, bytes32 reason) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            3, 0, bytes32("REDEEM")
        );
        assertFalse(allow);
        assertEq(reason, ReasonCodes.REDEMPTION);
    }

    function test_6D_redemptionEligibility_skippedForNonRedeemAction() public {
        vm.prank(issuer);
        compliance.setRedemptionIneligible(address(0xAAAA), true);
        // action is TRANSFER, not REDEEM → rule skipped.
        (bool allow, ) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            3, 0, bytes32("TRANSFER")
        );
        assertTrue(allow);
    }

    function test_6D_redemptionEligibility_allowsEligibleHolder() public {
        (bool allow, ) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            3, 0, bytes32("REDEEM")
        );
        assertTrue(allow);
    }

    // ----- priority ordering across rules -----------------------------------

    /// @notice Sanctions fires before transfer-eligibility when both apply.
    function test_6D_priority_sanctionsBeforeTransferIneligibility() public {
        vm.startPrank(issuer);
        compliance.addSanctionedAddress(address(0xAAAA));
        compliance.setTransferIneligible(address(0xAAAA), true);
        vm.stopPrank();

        (, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 1, ""
        );
        assertEq(reason, ReasonCodes.SANCTIONS);
    }

    /// @notice Transfer-eligibility fires before threshold when both apply.
    function test_6D_priority_transferEligibilityBeforeThreshold() public {
        vm.startPrank(issuer);
        compliance.setTransferIneligible(address(0xAAAA), true);
        compliance.setTransactionThreshold(1);
        vm.stopPrank();

        (, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 100, ""
        );
        assertEq(reason, ReasonCodes.TRANSFER_INELIGIBLE);
    }

    /// @notice Threshold fires before AML when amount exceeds both.
    function test_6D_priority_thresholdBeforeAml() public {
        vm.startPrank(issuer);
        compliance.setTransactionThreshold(1_000);
        compliance.setAmlThreshold(5_000);
        vm.stopPrank();

        (, bytes32 reason) = compliance.evaluate(
            address(this), address(0xAAAA), address(0xBBBB), 10_000, ""
        );
        assertEq(reason, ReasonCodes.THRESHOLD);
    }

    /// @notice Extended rules fire after basic rules pass. If a basic rule
    ///         rejects, extended rules are not evaluated.
    function test_6D_priority_basicRulesBeforeExtended() public {
        vm.startPrank(issuer);
        compliance.addSanctionedAddress(address(0xAAAA));
        compliance.setMinInvestorTier(3);
        vm.stopPrank();

        (, bytes32 reason) = compliance.evaluateWithDisclosure(
            address(this), address(0xAAAA), address(0xBBBB), 1, "",
            1, 0, bytes32("TRANSFER")
        );
        assertEq(reason, ReasonCodes.SANCTIONS);
    }
}
