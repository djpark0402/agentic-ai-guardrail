package com.aag.admin.apikey;

import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLog;
import com.aag.admin.audit.AuditLogRepository;
import com.aag.admin.policy.Policy;
import com.aag.admin.policy.PolicyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class InternalApiKeyFilterTest {

    @Autowired MockMvc mockMvc;
    @Autowired InternalApiKeyRepository apiKeyRepository;
    @Autowired InternalApiKeyService apiKeyService;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired PolicyRepository policyRepository;

    private String validKey;

    @BeforeEach
    void seed() {
        auditLogRepository.deleteAll();
        apiKeyRepository.deleteAll();
        policyRepository.deleteAll();

        Policy p = new Policy();
        p.setName("active");
        p.setUse(true);
        policyRepository.save(p);

        InternalApiKeyRequest req = new InternalApiKeyRequest();
        req.setName("k");
        validKey = apiKeyService.create(req).plainKey();
        auditLogRepository.deleteAll();
    }

    @Test
    void gatewayEndpoint_withValidKey_returns200_updatesLastUsedAt_writesSuccessAudit() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isOk());

        List<InternalApiKey> keys = apiKeyRepository.findAll();
        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).getLastUsedAt()).isNotNull();

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.APIKEY_AUTH
                && l.getActionId() == ActorType.GATEWAY && l.isSuccess());
    }

    @Test
    void gatewayEndpoint_withoutHeader_returns401_writesFailAudit() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/policies/active"))
                .andExpect(status().isUnauthorized());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.APIKEY_AUTH
                && l.getActionId() == ActorType.GATEWAY && !l.isSuccess()
                && l.getDetail().contains("missing"));
    }

    @Test
    void gatewayEndpoint_withUnknownKey_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", "iak_deadbeef"))
                .andExpect(status().isUnauthorized());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.APIKEY_AUTH && !l.isSuccess());
    }

    @Test
    void gatewayEndpoint_withRevokedKey_returns401() throws Exception {
        InternalApiKey key = apiKeyRepository.findAll().get(0);
        apiKeyService.revoke(key);
        auditLogRepository.deleteAll();

        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void gatewayEndpoint_withExpiredKey_returns401() throws Exception {
        InternalApiKey key = apiKeyRepository.findAll().get(0);
        key.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
        apiKeyRepository.save(key);
        auditLogRepository.deleteAll();

        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void nonGatewayEndpoint_isNotAffectedByFilter() throws Exception {
        mockMvc.perform(get("/api/v1/policies"))
                .andExpect(status().isOk());
    }
}
