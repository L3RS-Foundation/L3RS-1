// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: DESIGN.md §15 (Deployment flow), L3RS-1 v1.0.0 §2 (Asset Object),
//         §3 (Identity Binding), §5 (Governance), §12 (Legal Mirror),
//         08-deployment-target.md (Base Sepolia / Base Mainnet).
//
// Phase One deployment script. Deploys the four production contracts plus the
// MockZKVerifier placeholder, activates the asset (ISSUED → ACTIVE), sets the
// fee recipient if configured, and registers the first policy binding if a
// policy identifier is provided. All parameters are read from environment
// variables so the same script serves Base Sepolia and Base Mainnet; see
// DESIGN.md §15 for the full parameter list and checklist.
//
// Three entry points:
//   run()                       — production. Reads env vars, broadcasts under
//                                 DEPLOYER_PRIVATE_KEY.
//   deployFromEnv()             — reads env vars but does not broadcast;
//                                 useful for forge-script dry runs and tests.
//   deployFromConfig(cfg)       — pure-logic deploy from an explicit config
//                                 struct; used by test/script/Deploy.t.sol.

import {Script} from "forge-std/Script.sol";

import {ComplianceModule} from "../src/ComplianceModule.sol";
import {IdentityAttestation} from "../src/IdentityAttestation.sol";
import {L3RS1Asset} from "../src/L3RS1Asset.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {MockZKVerifier} from "../src/MockZKVerifier.sol";
import {IZKVerifier} from "../src/interfaces/IZKVerifier.sol";

contract DeployPhaseOne is Script {
    // ----- types --------------------------------------------------------

    /// @notice Every parameter the deploy script needs.
    /// @dev `feeRecipient` may be address(0) to skip the setFeeRecipient call.
    ///      `policyId` may be bytes32(0) to skip the first PolicyRegistry
    ///      registration; in that case Phase One deploys with an empty
    ///      policy registry, and the first policy is registered in a
    ///      subsequent governance transaction.
    struct DeployConfig {
        address issuer;
        address[] governanceAuthorities;
        address[] initialVAs;
        bytes2 jurisdiction;
        uint8 idTier;
        address feeRecipient;
        bytes32 policyId;
    }

    /// @notice Every contract produced by a deploy. Returned so callers —
    ///         both production scripts and the test harness — can address
    ///         each deployed instance by name.
    struct Deployment {
        ComplianceModule compliance;
        IdentityAttestation identity;
        PolicyRegistry registry;
        L3RS1Asset asset;
        MockZKVerifier zkVerifier;
    }

    // ----- entry points -------------------------------------------------

    /// @notice Production entry point. Reads config from env vars, broadcasts
    ///         under DEPLOYER_PRIVATE_KEY.
    /// @dev The deployer private key must correspond to the same address as
    ///      ISSUER_ADDR. Phase One requires the deployer to be the issuer
    ///      because `L3RS1Asset.activate()` is `onlyIssuer` and the script
    ///      activates as part of the same deploy transaction.
    function run() external returns (Deployment memory d) {
        DeployConfig memory cfg = _loadConfigFromEnv();
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        require(
            vm.addr(deployerKey) == cfg.issuer,
            "Deploy: DEPLOYER_PRIVATE_KEY must match ISSUER_ADDR"
        );
        vm.startBroadcast(deployerKey);
        d = _deploy(cfg);
        vm.stopBroadcast();
    }

    /// @notice Env-var deploy without broadcast. Used by dry-run tooling and
    ///         by the test harness.
    /// @dev Inside this function the script pranks as the issuer so the
    ///      subsequent `new Contract()` creations and post-deploy calls go
    ///      out with `msg.sender == cfg.issuer`. This mirrors what
    ///      `vm.startBroadcast(deployerKey)` does in `run()` under a real
    ///      `forge script` invocation, and makes `deployFromEnv` /
    ///      `deployFromConfig` safe to call from a Foundry test without the
    ///      caller having to understand the msg.sender propagation rules.
    function deployFromEnv() external returns (Deployment memory d) {
        DeployConfig memory cfg = _loadConfigFromEnv();
        vm.startPrank(cfg.issuer);
        d = _deploy(cfg);
        vm.stopPrank();
    }

    /// @notice Config-struct deploy without broadcast. Used by the test harness.
    /// @dev See `deployFromEnv` for why the internal prank is required.
    function deployFromConfig(DeployConfig memory cfg) external returns (Deployment memory d) {
        vm.startPrank(cfg.issuer);
        d = _deploy(cfg);
        vm.stopPrank();
    }

    // ----- deployment logic ---------------------------------------------

    /// @dev The eight deployment steps documented in DESIGN.md §15.
    function _deploy(DeployConfig memory cfg) internal returns (Deployment memory d) {
        // Step 1: MockZKVerifier — IZKVerifier dependency for IdentityAttestation.
        //         Phase One placeholder per §5b. Real verifier swap via
        //         IdentityAttestation.setZKVerifier before mainnet (§9 TODO 14).
        d.zkVerifier = new MockZKVerifier();

        // Step 2: IdentityAttestation — governance authorities, initial VAs, zk verifier.
        d.identity = new IdentityAttestation(cfg.governanceAuthorities, cfg.initialVAs, d.zkVerifier);

        // Step 3: ComplianceModule — same governance authority set.
        //         Owner is msg.sender (the deployer); rule setters are owner-gated.
        d.compliance = new ComplianceModule(cfg.governanceAuthorities);

        // Step 4: PolicyRegistry — same governance authority set.
        //         Owner is msg.sender (the deployer); register() is owner-gated,
        //         amend()/retire() are quorum-gated.
        d.registry = new PolicyRegistry(cfg.governanceAuthorities);

        // Step 5: L3RS1Asset — asset-level parameters plus references to the three
        //         previously-deployed contracts. Starts in ISSUED per §2.5.
        d.asset = new L3RS1Asset({
            issuer_: cfg.issuer,
            jurisdiction_: cfg.jurisdiction,
            idTier_: cfg.idTier,
            compliance_: d.compliance,
            identity_: d.identity,
            registry_: d.registry,
            authorities_: cfg.governanceAuthorities
        });

        // Step 6: activate — ISSUED → ACTIVE. `onlyIssuer`; the deployer must
        //         be the issuer for this call to succeed. The production
        //         contract is now ready to accept transfers and governance
        //         actions at the end of the deploy transaction.
        d.asset.activate();

        // Step 7: fee recipient — optional. When provided, routes the 25-bps
        //         transfer fee per §6. When omitted (address(0)), fees are
        //         not routed (netAmount == amount per `_executeTransfer`).
        if (cfg.feeRecipient != address(0)) {
            d.asset.setFeeRecipient(cfg.feeRecipient);
        }

        // Step 8: first policy binding — optional. When provided, registers
        //         `policyId → compliance` as version 1. Owner-gated; the
        //         deployer is the PolicyRegistry owner by construction.
        //         When omitted, Phase Five bridge consumers cannot query
        //         currentHash(policyId) until a subsequent governance
        //         action registers a policy.
        if (cfg.policyId != bytes32(0)) {
            d.registry.register(cfg.policyId, address(d.compliance));
        }
    }

    // ----- config loading ----------------------------------------------

    /// @dev Reads every config field from environment variables with typed
    ///      parsers. Every required field reverts with the env var name if
    ///      unset; optional fields (FEE_RECIPIENT, POLICY_ID) default to
    ///      the zero-sentinel value that disables the corresponding step.
    function _loadConfigFromEnv() internal view returns (DeployConfig memory cfg) {
        cfg.issuer = vm.envAddress("ISSUER_ADDR");
        cfg.governanceAuthorities = vm.envAddress("GOVERNANCE_AUTHORITIES", ",");
        cfg.initialVAs = vm.envAddress("INITIAL_VAS", ",");

        string memory juris = vm.envString("JURISDICTION");
        require(bytes(juris).length == 2, "Deploy: JURISDICTION must be 2 chars");
        cfg.jurisdiction = bytes2(bytes(juris));

        uint256 tier = vm.envUint("ID_TIER");
        require(tier <= 3, "Deploy: ID_TIER must be 0..3");
        cfg.idTier = uint8(tier);

        cfg.feeRecipient = vm.envOr("FEE_RECIPIENT", address(0));
        cfg.policyId = vm.envOr("POLICY_ID", bytes32(0));
    }
}
