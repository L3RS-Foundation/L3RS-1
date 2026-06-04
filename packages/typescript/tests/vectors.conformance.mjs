/**
 * Cross-language compliance conformance for the TypeScript SDK.
 * Imports the BUILT engine (../dist) and runs the shared corpus
 * (test-vectors/compliance_vectors.json), asserting each decision matches the
 * golden expectation. §11.5.  Run: npm run test:vectors
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { evaluateCompliance } from "../dist/index.js";

const corpusPath = join(import.meta.dirname, "../../../test-vectors/compliance_vectors.json");
const corpus = JSON.parse(readFileSync(corpusPath, "utf8"));

let pass = 0, fail = 0;
for (const tc of corpus.cases) {
  const ctx = {
    amount: BigInt(tc.amount), timestamp: tc.timestamp, jurisdiction: tc.jurisdiction,
    sender: tc.sender, receiver: tc.receiver, attestations: tc.attestations,
  };
  const d = evaluateCompliance(tc.module, tc.state, ctx);
  const got = d.blockedBy ? d.blockedBy.ruleId : null;
  if (d.allowed === tc.expected.allowed && got === tc.expected.blockedBy) {
    pass++;
  } else {
    fail++;
    console.error(`  FAIL ${tc.name}: got allowed=${d.allowed} blockedBy=${got}, ` +
      `expected allowed=${tc.expected.allowed} blockedBy=${tc.expected.blockedBy}`);
  }
}
console.log(`TypeScript compliance vectors: ${pass} passed, ${fail} failed (of ${corpus.cases.length})`);
process.exit(fail ? 1 : 0);
