// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Theorem 15.4 — Double Issuance Prevention.
// Source: L3RS-1 v1.0.0 §15.6. Mapped in 06-theorems.md Part A.
//
// Formal statement: "Global supply remains constant under lock-and-mint or
// burn-and-mint transfer models."
//
// Phase One applicability: partial. Phase One implements supply accounting on Base.
// The cross-chain mint/burn coupling is Phase Five. In Phase One, total supply on
// Base tracks mint and burn operations atomically. Total supply never changes via
// any path that is not a recorded mint or burn.

import {BaseTest} from "../BaseTest.t.sol";

contract Theorem04_DoubleIssuance is BaseTest {
    function test_T4_supplyIncreasesOnlyByMint() public {
        uint256 supplyBefore = asset.totalSupply();
        uint256 mintAmount = 1_000_000;

        vm.prank(issuer);
        asset.issue(holderA, mintAmount);

        assertEq(asset.totalSupply(), supplyBefore + mintAmount, "T4: totalSupply did not rise by mint amount");
        assertEq(asset.mintedTotal(), supplyBefore + mintAmount, "T4: mintedTotal not updated");
    }

    function test_T4_supplyDecreasesOnlyByBurn() public {
        vm.prank(issuer);
        asset.issue(holderA, 1_000_000);

        uint256 supplyBefore = asset.totalSupply();
        uint256 burnedBefore = asset.burnedTotal();

        _whitelistAndGrantId(holderA, holderB);

        vm.prank(holderA);
        asset.redeem(500_000);

        assertEq(asset.totalSupply(), supplyBefore - 500_000, "T4: totalSupply did not fall by burn amount");
        assertEq(asset.burnedTotal(), burnedBefore + 500_000, "T4: burnedTotal not updated");
    }

    // Theorem 15.4 invariants moved to test/invariants/T4_Handler_SupplyInvariant.t.sol
    // as of step 6C (Handler-based campaign per DESIGN.md §9 TODO 10). The
    // contract-state supply identity is still checked there via the Handler's
    // ghost cross-check. This file retains the unit tests for mint/burn that
    // exercise specific supply deltas against fixed inputs.

    function _whitelistAndGrantId(address from, address to) internal {
        _grantAttestationVA(from, JURISDICTION_GB, 2, block.timestamp + 365 days);
        _grantAttestationVA(to, JURISDICTION_US, 2, block.timestamp + 365 days);
        vm.prank(issuer);
        compliance.allowJurisdictionPair(JURISDICTION_GB, JURISDICTION_US);
    }
}
