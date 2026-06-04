package foundation.l3rs1;

import foundation.l3rs1.crypto.L3rsCrypto;
import foundation.l3rs1.modules.L3rsModules;
import foundation.l3rs1.modules.L3rsModules.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import java.math.BigInteger;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class L3rsSdkTest {

    static final String PUBKEY   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    static final long   TS       = 1740355200L;
    static final String NONCE    = "0000000000000001";
    static final String EXPECTED = "593f0dfb3da2fb8e8e21059e26f4a1875e9059a6d9d634e3065541e6c193506a";
    static final long   NOW      = 1740355200L;

    // ── §2.2 Asset_ID ─────────────────────────────────────────────────────────

    @Test @DisplayName("§2.2 Asset_ID canonical vector")
    void assetIdVector() { assertEquals(EXPECTED, L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE)); }

    @Test @DisplayName("§2.2 Asset_ID is 64 chars")
    void assetIdLength() { assertEquals(64, L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE).length()); }

    @Test @DisplayName("§2.2 Asset_ID deterministic")
    void assetIdDeterministic() {
        assertEquals(L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE),
                     L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE));
    }

    @Test @DisplayName("§2.2 Asset_ID nonce sensitive")
    void assetIdNonceSensitive() {
        assertNotEquals(L3rsCrypto.constructAssetId(PUBKEY, TS, NONCE),
                        L3rsCrypto.constructAssetId(PUBKEY, TS, "0000000000000002"));
    }

    // ── §13.11 Canonical JSON ─────────────────────────────────────────────────

    @Test @DisplayName("§13.11 Keys sorted")
    void canonicalSort() {
        assertEquals("{\"a\":1,\"m\":2,\"z\":3}",
            L3rsCrypto.canonicalize(Map.of("z",3,"a",1,"m",2)));
    }

    @Test @DisplayName("§13.11 Deterministic")
    void canonicalDeterministic() {
        var obj = Map.of("b", 2, "a", 1);
        assertEquals(L3rsCrypto.canonicalize(obj), L3rsCrypto.canonicalize(obj));
    }

    // ── §2.5 State Transitions ────────────────────────────────────────────────

    @ParameterizedTest(name = "{0} --{1}--> {2}")
    @CsvSource({
        "ISSUED,ACTIVATION,ACTIVE", "ACTIVE,BREACH,RESTRICTED",
        "ACTIVE,FREEZE,FROZEN", "RESTRICTED,CLEARED,ACTIVE",
        "FROZEN,RELEASE,ACTIVE", "ACTIVE,REDEMPTION,REDEEMED",
        "REDEEMED,FINALIZATION,BURNED", "ACTIVE,SUSPENSION,SUSPENDED",
        "SUSPENDED,REINSTATEMENT,ACTIVE",
    })
    void validTransition(String from, String trigger, String expected) {
        var r = L3rsModules.applyStateTransition(AssetState.valueOf(from), trigger);
        assertTrue(r.success());
        assertEquals(AssetState.valueOf(expected), r.newState());
    }

    @Test @DisplayName("§2.5 BURNED is terminal")
    void burnedTerminal() {
        assertFalse(L3rsModules.applyStateTransition(AssetState.BURNED, "ACTIVATION").success());
    }

    @Test @DisplayName("§2.5 Invalid transition rejected")
    void invalidTransition() {
        assertFalse(L3rsModules.applyStateTransition(AssetState.ISSUED, "FREEZE").success());
    }

    // ── §8.3 CID ─────────────────────────────────────────────────────────────

    @Test @DisplayName("§8.3 CID deterministic")
    void cidDeterministic() {
        String A="a".repeat(64), B="b".repeat(64), C="c".repeat(64), D="d".repeat(64);
        assertEquals(L3rsCrypto.constructCID(A,B,C,D,1000L),
                     L3rsCrypto.constructCID(A,B,C,D,1000L));
    }

    @Test @DisplayName("§8.3 CID timestamp sensitive")
    void cidTimestampSensitive() {
        String A="a".repeat(64), B="b".repeat(64), C="c".repeat(64), D="d".repeat(64);
        assertNotEquals(L3rsCrypto.constructCID(A,B,C,D,1000L),
                        L3rsCrypto.constructCID(A,B,C,D,1001L));
    }

    // ── §6.12 Fee Validation ──────────────────────────────────────────────────

    @Test @DisplayName("§6.12 Valid fee module accepted")
    void validFee() {
        var fm = new FeeModule(100, List.of(
            new FeeAllocation("a",2000), new FeeAllocation("b",3000),
            new FeeAllocation("c",2000), new FeeAllocation("d",2500),
            new FeeAllocation("e",500)));
        assertDoesNotThrow(() -> L3rsModules.validateFeeModule(fm));
    }

    @Test @DisplayName("§6.12 Partial allocation rejected")
    void partialFeeRejected() {
        var fm = new FeeModule(100, List.of(new FeeAllocation("x", 5000)));
        assertThrows(IllegalArgumentException.class, () -> L3rsModules.validateFeeModule(fm));
    }

    // ── §3.6 Identity Status ──────────────────────────────────────────────────

    @Test @DisplayName("§3.6 VALID status")
    void identityValid() {
        var r = new IdentityRecord("","","US",9_999_999_999L,false);
        assertEquals(IdentityStatus.VALID, L3rsModules.identityStatus(r, NOW));
    }

    @Test @DisplayName("§3.6 EXPIRED status")
    void identityExpired() {
        var r = new IdentityRecord("","","US",1_000_000_000L,false);
        assertEquals(IdentityStatus.EXPIRED, L3rsModules.identityStatus(r, NOW));
    }

    @Test @DisplayName("§3.6 REVOKED status")
    void identityRevoked() {
        var r = new IdentityRecord("","","US",9_999_999_999L,true);
        assertEquals(IdentityStatus.REVOKED, L3rsModules.identityStatus(r, NOW));
    }

    // ── §9.6 Replay Protection ────────────────────────────────────────────────

    @Test @DisplayName("§9.6 Same event is replay")
    void sameEventIsReplay() {
        var ev = new TransferEvent("a","alice","bob",BigInteger.valueOf(1000),NONCE,TS);
        var txId = L3rsCrypto.constructTxId(ev.sender(),ev.receiver(),ev.amount(),ev.nonce(),ev.timestamp());
        var history = new HashSet<>(Set.of(txId));
        assertTrue(L3rsModules.isReplay(ev, history));
    }

    @Test @DisplayName("§9.6 Different nonce not replay")
    void differentNonceNotReplay() {
        var ev1 = new TransferEvent("a","alice","bob",BigInteger.valueOf(1000),NONCE,TS);
        var ev2 = new TransferEvent("a","alice","bob",BigInteger.valueOf(1000),"0000000000000002",TS);
        var txId = L3rsCrypto.constructTxId(ev1.sender(),ev1.receiver(),ev1.amount(),ev1.nonce(),ev1.timestamp());
        var history = new HashSet<>(Set.of(txId));
        assertFalse(L3rsModules.isReplay(ev2, history));
    }

    // ── §4 Compliance engine (fail-closed, §10.15 attestations) ───────────────

    private static ComplianceModule sanctionsModule() {
        return new ComplianceModule(List.of(new ComplianceRule(
            "r1", RuleType.SANCTIONS_SCREENING, "*", "TRANSFER", 1, EnforcementAction.REJECT,
            Map.of("sourceHash", "OFAC-2026-06-04", "minVersion", 7))));
    }

    private static EvalContext ctx(OracleAttestation att) {
        Map<RuleType, OracleAttestation> m = new HashMap<>();
        if (att != null) m.put(RuleType.SANCTIONS_SCREENING, att);
        return new EvalContext(100L, NOW, "GE",
            new PartyAttributes(IdentityStatus.VALID, "GE", "", 0L),
            new PartyAttributes(IdentityStatus.VALID, "GE", "", 0L), m);
    }

    @Test @DisplayName("§4 fails closed without attestation")
    void complianceFailsClosedWithoutAttestation() {
        assertFalse(L3rsModules.evaluateCompliance(sanctionsModule(), AssetState.ACTIVE, ctx(null)).allowed());
    }

    @Test @DisplayName("§10.15 blocks on source-hash mismatch")
    void complianceBlocksWrongHash() {
        assertFalse(L3rsModules.evaluateCompliance(sanctionsModule(), AssetState.ACTIVE,
            ctx(new OracleAttestation(true, 9, "WRONG", NOW + 3600))).allowed());
    }

    @Test @DisplayName("§10.15 blocks on stale version")
    void complianceBlocksStaleVersion() {
        assertFalse(L3rsModules.evaluateCompliance(sanctionsModule(), AssetState.ACTIVE,
            ctx(new OracleAttestation(true, 3, "OFAC-2026-06-04", NOW + 3600))).allowed());
    }

    @Test @DisplayName("§10.15 blocks expired attestation")
    void complianceBlocksExpired() {
        assertFalse(L3rsModules.evaluateCompliance(sanctionsModule(), AssetState.ACTIVE,
            ctx(new OracleAttestation(true, 9, "OFAC-2026-06-04", NOW - 1))).allowed());
    }

    @Test @DisplayName("§4 blocks on sanctions hit")
    void complianceBlocksSanctionsHit() {
        assertFalse(L3rsModules.evaluateCompliance(sanctionsModule(), AssetState.ACTIVE,
            ctx(new OracleAttestation(false, 9, "OFAC-2026-06-04", NOW + 3600))).allowed());
    }

    @Test @DisplayName("§4 allows fully valid attested transfer")
    void complianceAllowsValid() {
        assertTrue(L3rsModules.evaluateCompliance(sanctionsModule(), AssetState.ACTIVE,
            ctx(new OracleAttestation(true, 9, "OFAC-2026-06-04", NOW + 3600))).allowed());
    }

    @Test @DisplayName("§4.4 geographic restriction blocks")
    void complianceGeographicBlocks() {
        ComplianceModule mod = new ComplianceModule(List.of(new ComplianceRule(
            "g", RuleType.GEOGRAPHIC_RESTRICTION, "*", "TRANSFER", 1, EnforcementAction.REJECT,
            Map.of("blockedJurisdictions", List.of("GE")))));
        assertFalse(L3rsModules.evaluateCompliance(mod, AssetState.ACTIVE, ctx(null)).allowed());
    }

    @Test @DisplayName("§4.4 transfer eligibility blocks on invalid identity")
    void complianceTransferEligibilityBlocksBadIdentity() {
        EvalContext c = new EvalContext(100L, NOW, "GE",
            new PartyAttributes(IdentityStatus.VALID, "GE", "", 0L),
            new PartyAttributes(IdentityStatus.EXPIRED, "GE", "", 0L), new HashMap<>());
        ComplianceModule mod = new ComplianceModule(List.of(new ComplianceRule(
            "t", RuleType.TRANSFER_ELIGIBILITY, "*", "TRANSFER", 1, EnforcementAction.REJECT, Map.of())));
        assertFalse(L3rsModules.evaluateCompliance(mod, AssetState.ACTIVE, c).allowed());
    }
}
