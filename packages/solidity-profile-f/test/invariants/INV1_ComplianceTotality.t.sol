// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// INV-1 — Compliance Totality.
// Source: Architecture v1.1 §7. Mapped in 06-theorems.md Part E.
// Full applicability in Phase One.
//
// Statement: ComplianceModule.evaluate is a total decision function. It never
// reverts. For every input it returns a (allow, reasonCode) pair. On block, the
// reason code is non-zero. On allow, the reason code is zero.
//
// This invariant protects the Layer 2 precondition: PG[Σ] in Phase Two relies on
// every honest MPC party computing the same allow/reject bit on the same (ctx).
// A ComplianceModule that reverts on adversarial inputs would let an adversary
// abort the signing protocol silently rather than trigger a structured reject.

import {Test} from "forge-std/Test.sol";
import {IComplianceModuleF} from "../../src/interfaces/IComplianceModuleF.sol";
import {ComplianceModule} from "../../src/ComplianceModule.sol";
import {ReasonCodes} from "../../src/libraries/ReasonCodes.sol";

contract INV1_ComplianceTotality is Test {
    ComplianceModule internal compliance;
    address internal issuer = makeAddr("issuer");

    function setUp() public {
        address[] memory authorities = new address[](3);
        authorities[0] = makeAddr("gov1");
        authorities[1] = makeAddr("gov2");
        authorities[2] = makeAddr("gov3");

        vm.prank(issuer);
        compliance = new ComplianceModule(authorities);

        targetContract(address(compliance));
    }

    /// @notice Fuzzed: for any inputs, evaluate returns rather than reverts.
    function test_INV1_evaluateNeverReverts(
        address assetRef,
        address sender,
        address receiver,
        uint256 amount,
        bytes calldata context
    ) public view {
        // The unused-variable access below exists to satisfy the compiler; the
        // purpose is the try-success path that follows.
        assetRef;
        try compliance.evaluate(assetRef, sender, receiver, amount, context) returns (bool, bytes32) {
            // pass
        } catch {
            revert("INV-1: evaluate reverted on adversarial input");
        }
    }

    /// @notice Fuzzed: if evaluate returns false, the reason code is non-zero. If it
    ///         returns true, the reason code is zero. No mixed states.
    function test_INV1_allowAndReasonAreExclusive(
        address assetRef,
        address sender,
        address receiver,
        uint256 amount,
        bytes calldata context
    ) public view {
        (bool allow, bytes32 reason) = compliance.evaluate(assetRef, sender, receiver, amount, context);
        if (allow) {
            assertEq(reason, bytes32(0), "INV-1: allow=true with non-zero reasonCode");
        } else {
            assertTrue(reason != bytes32(0), "INV-1: allow=false with zero reasonCode");
        }
    }

    /// @notice Foundry invariant: a counter of reverts observed during invariant
    ///         execution. This must stay at zero throughout the campaign.
    function invariant_INV1_noRevertsEver() public view {
        assertEq(compliance.observedRevertCount(), 0, "INV-1: evaluate reverted at least once");
    }
}
