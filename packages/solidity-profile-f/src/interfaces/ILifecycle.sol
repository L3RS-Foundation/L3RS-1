// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.26;

// Source: L3RS-1 v1.0.0 §2.4 (lifecycle enumeration), §2.5 (transition matrix),
//         07-profile-f.md §S (normative state naming).
// The T3RRA Architecture paper Figure 4 and Cryptographic Spec Figure 5 use Locked and
// Restored in place of RESTRICTED and REDEEMED. The L3RS-1 names are normative here.

/// @title ILifecycle
/// @notice The seven L3RS-1 lifecycle states and the transition events.
/// @dev The state set is closed and ordered per L3RS-1 §2.4. Phase One exposes every
///      state. Every transition is atomic and deterministic per §2.5.
interface ILifecycle {
    enum State {
        ISSUED,
        ACTIVE,
        RESTRICTED,
        FROZEN,
        SUSPENDED,
        REDEEMED,
        BURNED
    }

    // Transition triggers per L3RS-1 §2.5 transition matrix.
    enum Trigger {
        ACTIVATION,
        COMPLIANCE_BREACH,
        GOVERNANCE_FREEZE,
        COMPLIANCE_CLEARED,
        OVERRIDE_RELEASE,
        REDEMPTION,
        FINALIZATION
    }

    event StateTransition(State indexed from, State indexed to, Trigger indexed trigger, bytes32 txId);
}
