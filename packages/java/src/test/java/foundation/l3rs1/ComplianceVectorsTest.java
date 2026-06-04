package foundation.l3rs1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import foundation.l3rs1.modules.L3rsModules;
import foundation.l3rs1.modules.L3rsModules.*;
import org.junit.jupiter.api.Test;
import java.io.File;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Cross-language compliance conformance: runs the shared corpus
 * (test-vectors/compliance_vectors.json) through the Java engine and asserts
 * every decision matches the golden expectation. §11.5.
 */
class ComplianceVectorsTest {

    private static File locateCorpus() {
        for (String p : new String[]{
                "../../test-vectors/compliance_vectors.json",
                "../../../test-vectors/compliance_vectors.json",
                "test-vectors/compliance_vectors.json"}) {
            File f = new File(p);
            if (f.exists()) return f;
        }
        throw new IllegalStateException("compliance_vectors.json not found from " + new File(".").getAbsolutePath());
    }

    private static PartyAttributes party(JsonNode p) {
        return new PartyAttributes(
            IdentityStatus.valueOf(p.get("identityStatus").asText()),
            p.get("jurisdiction").asText(""),
            p.get("investorClass").asText(""),
            p.get("acquisitionTime").asLong());
    }

    @Test
    void complianceCorpusMatchesGolden() throws Exception {
        ObjectMapper om = new ObjectMapper();
        JsonNode corpus = om.readTree(locateCorpus());
        List<String> failures = new ArrayList<>();
        int count = 0;

        for (JsonNode tc : corpus.get("cases")) {
            count++;
            String name = tc.get("name").asText();

            Map<RuleType, OracleAttestation> att = new HashMap<>();
            JsonNode an = tc.get("attestations");
            Iterator<String> it = an.fieldNames();
            while (it.hasNext()) {
                String k = it.next();
                JsonNode v = an.get(k);
                att.put(RuleType.valueOf(k), new OracleAttestation(
                    v.get("cleared").asBoolean(), v.get("version").asLong(),
                    v.get("sourceHash").asText(), v.get("validUntil").asLong()));
            }

            List<ComplianceRule> rules = new ArrayList<>();
            for (JsonNode r : tc.get("module").get("rules")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> params = om.convertValue(r.get("params"), Map.class);
                if (params == null) params = Map.of();
                rules.add(new ComplianceRule(
                    r.get("ruleId").asText(), RuleType.valueOf(r.get("ruleType").asText()),
                    r.get("scope").asText(), r.get("trigger").asText(""),
                    r.get("priority").asInt(), EnforcementAction.valueOf(r.get("action").asText()),
                    params));
            }
            ComplianceModule module = new ComplianceModule(rules);

            EvalContext ctx = new EvalContext(
                tc.get("amount").asLong(), tc.get("timestamp").asLong(), tc.get("jurisdiction").asText(),
                party(tc.get("sender")), party(tc.get("receiver")), att);

            ComplianceDecision dec = L3rsModules.evaluateCompliance(
                module, AssetState.valueOf(tc.get("state").asText()), ctx);

            String gotBlocked = dec.blockedBy() == null ? null : dec.blockedBy().ruleId();
            JsonNode exp = tc.get("expected");
            boolean expAllowed = exp.get("allowed").asBoolean();
            String expBlocked = exp.get("blockedBy").isNull() ? null : exp.get("blockedBy").asText();

            if (dec.allowed() != expAllowed || !Objects.equals(gotBlocked, expBlocked)) {
                failures.add(String.format(
                    "%s: got allowed=%s blockedBy=%s, expected allowed=%s blockedBy=%s",
                    name, dec.allowed(), gotBlocked, expAllowed, expBlocked));
            }
        }
        assertTrue(failures.isEmpty(), "Java compliance vector mismatches:\n" + String.join("\n", failures));
        System.out.println("Java compliance vectors: " + count + " passed");
    }
}
