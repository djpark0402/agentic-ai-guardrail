package com.aag.admin.gateway;

import com.aag.admin.agentkey.AgentApiKey;
import com.aag.admin.agentkey.AgentApiKeyRepository;
import com.aag.admin.agentkey.AgentApiKeyRequest;
import com.aag.admin.agentkey.AgentApiKeyService;
import com.aag.admin.apikey.InternalApiKeyRepository;
import com.aag.admin.apikey.InternalApiKeyRequest;
import com.aag.admin.apikey.InternalApiKeyService;
import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLog;
import com.aag.admin.audit.AuditLogRepository;
import com.aag.admin.policy.Policy;
import com.aag.admin.policy.PolicyRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class VerifyControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired AgentApiKeyRepository agentRepo;
    @Autowired AgentApiKeyService agentService;
    @Autowired InternalApiKeyRepository iakRepo;
    @Autowired InternalApiKeyService iakService;
    @Autowired PolicyRepository policyRepo;
    @Autowired AuditLogRepository auditLogRepo;

    private String agentApiKey;
    private String agentSecret;
    private Long agentKeyId;
    private String internalKey;

    @BeforeEach
    void seed() {
        auditLogRepo.deleteAll();
        agentRepo.deleteAll();
        iakRepo.deleteAll();
        policyRepo.deleteAll();

        Policy p = new Policy();
        p.setName("default-strict");
        p.setUse(true);
        p.setL1Enabled(true); p.setL2Enabled(false); p.setL3Enabled(true);
        p.setL4Enabled(true); p.setL5Enabled(false); p.setL6Enabled(true);
        policyRepo.save(p);

        AgentApiKeyRequest req = new AgentApiKeyRequest();
        req.setClientName("고객사A");
        AgentApiKeyService.Issued issued = agentService.create(req);
        agentApiKey = issued.plainApiKey();
        agentSecret = issued.plainSecret();
        agentKeyId = issued.entity().getId();

        InternalApiKeyRequest iakReq = new InternalApiKeyRequest();
        iakReq.setName("gateway-test");
        internalKey = iakService.create(iakReq).plainKey();

        auditLogRepo.deleteAll();
    }

    @Test
    void verify_validSignature_returnsValidTrueWithPolicyAndAudit() throws Exception {
        long ts = Instant.now().getEpochSecond();
        String nonce = "n-1";
        String body = "{\"prompt\":\"hello\"}";
        String bodyHash = sha256Hex(body);
        String sig = hmacSha256Hex(agentSecret, ts + "." + nonce + "." + bodyHash);

        Map<String, Object> req = Map.of(
                "apiKey", agentApiKey,
                "timestamp", String.valueOf(ts),
                "nonce", nonce,
                "bodyHash", bodyHash,
                "signature", sig
        );

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.clientName").value("고객사A"))
                .andExpect(jsonPath("$.agentKeyId").value(agentKeyId))
                .andExpect(jsonPath("$.policy.name").value("default-strict"))
                .andExpect(jsonPath("$.policy.l1Enabled").value(true))
                .andExpect(jsonPath("$.policy.l2Enabled").value(false));

        AgentApiKey updated = agentRepo.findAll().get(0);
        assertThat(updated.getLastUsedAt()).isNotNull();

        List<AuditLog> logs = auditLogRepo.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.AGENT_AUTH
                && l.getActionId() == ActorType.GATEWAY && l.isSuccess());
    }

    @Test
    void verify_invalidSignature_returnsValidFalse_reasonInvalidSignature() throws Exception {
        long ts = Instant.now().getEpochSecond();
        String bodyHash = sha256Hex("{}");

        Map<String, Object> req = Map.of(
                "apiKey", agentApiKey,
                "timestamp", String.valueOf(ts),
                "nonce", "n-2",
                "bodyHash", bodyHash,
                "signature", "deadbeef".repeat(8)
        );

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").value("invalid_signature"));
    }

    @Test
    void verify_timestampTooOld_returnsReasonTimestampSkew() throws Exception {
        long oldTs = Instant.now().minus(1, ChronoUnit.HOURS).getEpochSecond();
        String bodyHash = sha256Hex("");
        String sig = hmacSha256Hex(agentSecret, oldTs + ".n." + bodyHash);

        Map<String, Object> req = buildReq(agentApiKey, oldTs, "n", bodyHash, sig);

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.reason").value("timestamp_skew"));
    }

    @Test
    void verify_nonNumericTimestamp_returnsReasonTimestampSkew() throws Exception {
        Map<String, Object> req = buildReq(agentApiKey, "not-a-number", "n", sha256Hex(""), "x".repeat(64));

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("timestamp_skew"));
    }

    @Test
    void verify_unknownApiKey_returnsReasonUnknownKey() throws Exception {
        long ts = Instant.now().getEpochSecond();
        Map<String, Object> req = buildReq("ak_unknown_xxxxx", ts, "n", sha256Hex(""), "x".repeat(64));

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("unknown_key"));
    }

    @Test
    void verify_revokedKey_returnsReasonRevoked() throws Exception {
        AgentApiKey key = agentRepo.findAll().get(0);
        agentService.revoke(key);
        auditLogRepo.deleteAll();

        long ts = Instant.now().getEpochSecond();
        String bodyHash = sha256Hex("");
        String sig = hmacSha256Hex(agentSecret, ts + ".n." + bodyHash);

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildReq(agentApiKey, ts, "n", bodyHash, sig))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("revoked"));
    }

    @Test
    void verify_expiredKey_returnsReasonExpired() throws Exception {
        AgentApiKey key = agentRepo.findAll().get(0);
        key.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
        agentRepo.save(key);
        auditLogRepo.deleteAll();

        long ts = Instant.now().getEpochSecond();
        String bodyHash = sha256Hex("");
        String sig = hmacSha256Hex(agentSecret, ts + ".n." + bodyHash);

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildReq(agentApiKey, ts, "n", bodyHash, sig))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("expired"));
    }

    @Test
    void verify_noActivePolicy_returnsReasonNoActivePolicy() throws Exception {
        policyRepo.deleteAll();
        auditLogRepo.deleteAll();

        long ts = Instant.now().getEpochSecond();
        String bodyHash = sha256Hex("");
        String sig = hmacSha256Hex(agentSecret, ts + ".n." + bodyHash);

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildReq(agentApiKey, ts, "n", bodyHash, sig))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reason").value("no_active_policy"));
    }

    @Test
    void verify_missingField_returns400() throws Exception {
        Map<String, Object> req = new HashMap<>();
        req.put("apiKey", agentApiKey);

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .header("X-API-Key", internalKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void verify_withoutInternalApiKeyHeader_returns401() throws Exception {
        long ts = Instant.now().getEpochSecond();
        String bodyHash = sha256Hex("");
        String sig = hmacSha256Hex(agentSecret, ts + ".n." + bodyHash);

        mockMvc.perform(post("/api/v1/gateway/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(buildReq(agentApiKey, ts, "n", bodyHash, sig))))
                .andExpect(status().isUnauthorized());
    }

    private Map<String, Object> buildReq(String apiKey, long ts, String nonce, String bodyHash, String sig) {
        return buildReq(apiKey, String.valueOf(ts), nonce, bodyHash, sig);
    }

    private Map<String, Object> buildReq(String apiKey, String ts, String nonce, String bodyHash, String sig) {
        Map<String, Object> m = new HashMap<>();
        m.put("apiKey", apiKey);
        m.put("timestamp", ts);
        m.put("nonce", nonce);
        m.put("bodyHash", bodyHash);
        m.put("signature", sig);
        return m;
    }

    private static String sha256Hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return toHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    private static String hmacSha256Hex(String secret, String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return toHex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
