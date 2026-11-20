// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: DESIGN.md §15 (Deployment flow). Tests that `DeployPhaseOne`
// produces a fully-initialized Phase One system — five contracts deployed,
// asset activated, authorities and VAs populated, legal mirror hashed, and
// the first policy binding registered. The harness covers both entry
// points (deployFromConfig and deployFromEnv) so both paths are exercised.

import {Test} from "forge-std/Test.sol";

import {DeployPhaseOne} from "../../script/Deploy.s.sol";
import {ComplianceModule} from "../../src/ComplianceModule.sol";
import {IdentityAttestation} from "../../src/IdentityAttestation.sol";
import {L3RS1Asset} from "../../src/L3RS1Asset.sol";
import {PolicyRegistry} from "../../src/PolicyRegistry.sol";
import {MockZKVerifier} from "../../src/MockZKVerifier.sol";
import {ILifecycle} from "../../src/interfaces/ILifecycle.sol";

contract DeployScriptTest is Test {
    DeployPhaseOne internal script;

    address internal issuer;
    address internal gov1;
    address internal gov2;
    address internal gov3;
    address internal va1;
    address internal va2;
    address internal feeRecipient;

    bytes2 internal constant J_GB = bytes2("GB");
    uint8 internal constant ID_TIER = 2;
    bytes32 internal constant POLICY_ID = keccak256("PHASE_ONE_DEPLOY_TEST_POLICY");

    function setUp() public {
        script = new DeployPhaseOne();

        issuer = makeAddr("deploy-issuer");
        gov1 = makeAddr("deploy-gov1");
        gov2 = makeAddr("deploy-gov2");
        gov3 = makeAddr("deploy-gov3");
        va1 = makeAddr("deploy-va1");
        va2 = makeAddr("deploy-va2");
        feeRecipient = makeAddr("deploy-fee-recipient");
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    function _config() internal view returns (DeployPhaseOne.DeployConfig memory cfg) {
        address[] memory govs = new address[](3);
        govs[0] = gov1;
        govs[1] = gov2;
        govs[2] = gov3;

        address[] memory vas = new address[](2);
        vas[0] = va1;
        vas[1] = va2;

        cfg = DeployPhaseOne.DeployConfig({
            issuer: issuer,
            governanceAuthorities: govs,
            initialVAs: vas,
            jurisdiction: J_GB,
            idTier: ID_TIER,
            feeRecipient: feeRecipient,
            policyId: POLICY_ID
        });
    }

    function _deployAsIssuer() internal returns (DeployPhaseOne.Deployment memory) {
        // The script itself pranks as `cfg.issuer` internally per the
        // Deploy.s.sol comment on `deployFromConfig`. Callers don't need
        // to prank or broadcast; the script handles msg.sender propagation.
        return script.deployFromConfig(_config());
    }

    // ====================================================================
    // Contract-presence invariants
    // ====================================================================

    function test_deploy_allFiveContractsHaveCode() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();

        assertTrue(address(d.compliance) != address(0), "compliance deployed");
        assertTrue(address(d.identity) != address(0), "identity deployed");
        assertTrue(address(d.registry) != address(0), "registry deployed");
        assertTrue(address(d.asset) != address(0), "asset deployed");
        assertTrue(address(d.zkVerifier) != address(0), "zk verifier deployed");

        assertGt(address(d.compliance).code.length, 0, "compliance has code");
        assertGt(address(d.identity).code.length, 0, "identity has code");
        assertGt(address(d.registry).code.length, 0, "registry has code");
        assertGt(address(d.asset).code.length, 0, "asset has code");
        assertGt(address(d.zkVerifier).code.length, 0, "zk verifier has code");
    }

    // ====================================================================
    // Authority-set invariants
    // ====================================================================

    function test_deploy_authoritySetsMatchConfig() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();

        address[] memory complianceAuth = d.compliance.authorities();
        address[] memory identityAuth = d.identity.authorities();
        address[] memory registryAuth = d.registry.authorities();
        address[] memory assetAuth = d.asset.authorities();

        assertEq(complianceAuth.length, 3, "compliance N = 3");
        assertEq(identityAuth.length, 3, "identity N = 3");
        assertEq(registryAuth.length, 3, "registry N = 3");
        assertEq(assetAuth.length, 3, "asset N = 3");

        for (uint256 i = 0; i < 3; i++) {
            assertEq(complianceAuth[i], identityAuth[i], "identity auth i matches compliance");
            assertEq(identityAuth[i], registryAuth[i], "registry auth i matches identity");
            assertEq(registryAuth[i], assetAuth[i], "asset auth i matches registry");
        }

        assertEq(complianceAuth[0], gov1);
        assertEq(complianceAuth[1], gov2);
        assertEq(complianceAuth[2], gov3);
    }

    function test_deploy_vaSetMatchesConfig() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();

        address[] memory vas = d.identity.vaList();
        assertEq(vas.length, 2, "two initial VAs");
        assertEq(vas[0], va1, "va1 registered");
        assertEq(vas[1], va2, "va2 registered");

        assertTrue(d.identity.isVA(va1), "isVA(va1)");
        assertTrue(d.identity.isVA(va2), "isVA(va2)");
    }

    // ====================================================================
    // Asset-level invariants
    // ====================================================================

    function test_deploy_assetStateIsActive() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();
        assertEq(uint8(d.asset.currentState()), uint8(ILifecycle.State.ACTIVE), "state == ACTIVE");
    }

    function test_deploy_assetImmutablesMatchConfig() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();

        assertEq(d.asset.issuer(), issuer, "issuer");
        assertEq(bytes2(d.asset.jurisdiction()), J_GB, "jurisdiction");
        assertEq(d.asset.idTier(), ID_TIER, "idTier");
        assertEq(address(d.asset.compliance()), address(d.compliance), "compliance reference");
        assertEq(address(d.asset.identity()), address(d.identity), "identity reference");
        assertEq(address(d.asset.registry()), address(d.registry), "registry reference");
    }

    function test_deploy_assetSupplyInitializedToZero() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();
        assertEq(d.asset.totalSupply(), 0, "no supply at deploy");
        assertEq(d.asset.mintedTotal(), 0);
        assertEq(d.asset.burnedTotal(), 0);
    }

    // ====================================================================
    // Legal mirror invariants
    // ====================================================================

    function test_deploy_legalMirrorInitialized() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();

        // Legal mirror version is 1 at deploy; document is empty; hash is
        // the keccak of the canonical L3RS-1/LegalMirror/v1 tuple.
        assertEq(d.asset.legalVersion(), 1, "legal version == 1");

        bytes32 expected = keccak256(
            abi.encode(bytes32("L3RS-1/LegalMirror/v1"), bytes(""), J_GB, uint64(1))
        );
        assertEq(d.asset.legalHash(), expected, "legal hash matches empty-doc v1 derivation");

        // Cross-check against the public `computeLegalHash` derivation so the
        // script's test assertion matches the contract's own computation.
        bytes32 viaContract = d.asset.computeLegalHash("", J_GB, uint64(1));
        assertEq(d.asset.legalHash(), viaContract, "legal hash matches computeLegalHash");
    }

    // ====================================================================
    // Fee recipient
    // ====================================================================

    function test_deploy_feeRecipientSet() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();
        assertEq(d.asset.feeRecipient(), feeRecipient, "fee recipient set");
    }

    function test_deploy_feeRecipientOmittedWhenZero() public {
        DeployPhaseOne.DeployConfig memory cfg = _config();
        cfg.feeRecipient = address(0);

        DeployPhaseOne.Deployment memory d = script.deployFromConfig(cfg);

        assertEq(d.asset.feeRecipient(), address(0), "fee recipient stays zero when config has zero");
    }

    // ====================================================================
    // PolicyRegistry first binding
    // ====================================================================

    function test_deploy_firstPolicyRegistered() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();

        assertEq(
            d.registry.currentHash(POLICY_ID),
            d.compliance.complianceHash(),
            "registry currentHash matches compliance hash"
        );
    }

    function test_deploy_policyOmittedWhenZero() public {
        DeployPhaseOne.DeployConfig memory cfg = _config();
        cfg.policyId = bytes32(0);

        DeployPhaseOne.Deployment memory d = script.deployFromConfig(cfg);

        // No policy registered, so currentHash should revert on UnknownPolicy.
        vm.expectRevert();
        d.registry.currentHash(POLICY_ID);
    }

    // ====================================================================
    // Governance nonces are zero post-deploy
    // ====================================================================

    function test_deploy_governanceNoncesAreZero() public {
        DeployPhaseOne.Deployment memory d = _deployAsIssuer();

        assertEq(d.asset.governanceNonce(), 0, "asset gov nonce zero");
        assertEq(d.compliance.governanceNonce(), 0, "compliance gov nonce zero");
        assertEq(d.identity.governanceNonce(), 0, "identity gov nonce zero");
    }

    // ====================================================================
    // Env-var entry point
    // ====================================================================

    /// @notice Exercise the `deployFromEnv()` entry point so the env-var
    ///         parsing path is covered. Matches what a `forge script
    ///         --sig 'deployFromEnv()'` dry run does, or the `run()`
    ///         entry point minus the `vm.startBroadcast` call.
    function test_deploy_fromEnv() public {
        vm.setEnv("ISSUER_ADDR", vm.toString(issuer));
        vm.setEnv(
            "GOVERNANCE_AUTHORITIES",
            string.concat(vm.toString(gov1), ",", vm.toString(gov2), ",", vm.toString(gov3))
        );
        vm.setEnv("INITIAL_VAS", string.concat(vm.toString(va1), ",", vm.toString(va2)));
        vm.setEnv("JURISDICTION", "GB");
        vm.setEnv("ID_TIER", "2");
        vm.setEnv("FEE_RECIPIENT", vm.toString(feeRecipient));
        vm.setEnv("POLICY_ID", vm.toString(POLICY_ID));

        // `deployFromEnv` handles the prank internally per script comment.
        DeployPhaseOne.Deployment memory d = script.deployFromEnv();

        // Spot-check the key invariants against the env-deployed instance.
        assertEq(uint8(d.asset.currentState()), uint8(ILifecycle.State.ACTIVE));
        assertEq(d.asset.issuer(), issuer);
        assertEq(d.asset.feeRecipient(), feeRecipient);
        assertEq(d.registry.currentHash(POLICY_ID), d.compliance.complianceHash());
    }

    // ====================================================================
    // Negative-path: invalid config
    // ====================================================================

    /// @notice ID_TIER must be 0..3 per the L3RS-1 §3.2 tier range. The
    ///         script validates before calling the L3RS1Asset constructor.
    function test_deploy_revertsOnInvalidTier() public {
        DeployPhaseOne.DeployConfig memory cfg = _config();
        cfg.idTier = 4;

        vm.expectRevert(L3RS1Asset.InvalidTier.selector);
        script.deployFromConfig(cfg);
    }
}
