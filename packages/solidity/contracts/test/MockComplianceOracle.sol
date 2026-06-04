// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "../L3RS1Asset.sol"; // brings IComplianceOracle into scope

/**
 * @title MockComplianceOracle
 * @notice Test-only configurable evaluator implementing the §4 hook. Defaults to
 *         ALLOW; call setResult(false, ruleId) to simulate a blocking rule.
 *         A production oracle would apply the §10.15 attested-data contract.
 */
contract MockComplianceOracle is IComplianceOracle {
    bool    public allowed = true;
    bytes32 public ruleId  = bytes32(0);

    function setResult(bool allowed_, bytes32 ruleId_) external {
        allowed = allowed_;
        ruleId  = ruleId_;
    }

    function evaluate(bytes32, address, address, uint256)
        external view override returns (bool, bytes32)
    {
        return (allowed, ruleId);
    }
}
