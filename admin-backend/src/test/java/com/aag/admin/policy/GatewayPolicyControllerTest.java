package com.aag.admin.policy;

import com.aag.admin.apikey.InternalApiKeyRepository;
import com.aag.admin.apikey.InternalApiKeyRequest;
import com.aag.admin.apikey.InternalApiKeyService;
import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLog;
import com.aag.admin.audit.AuditLogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class GatewayPolicyControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired PolicyRepository policyRepository;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired InternalApiKeyRepository apiKeyRepository;
    @Autowired InternalApiKeyService apiKeyService;

    private String validKey;

    @BeforeEach
    void seed() throws Exception {
        auditLogRepository.deleteAll();
        policyRepository.deleteAll();
        apiKeyRepository.deleteAll();

        InternalApiKeyRequest req = new InternalApiKeyRequest();
        req.setName("gw-test");
        validKey = apiKeyService.create(req).plainKey();
        auditLogRepository.deleteAll();

        Long id = createPolicy("active-one");
        mockMvc.perform(post("/api/v1/policies/{id}/activate", id));
        auditLogRepository.deleteAll();
    }

    @Test
    void gatewayActive_withValidKey_returnsPolicy_andWritesGatewayAudit() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("active-one"));

        // 이 테스트는 컨트롤러 책임만 검증한다. 필터(APIKEY_AUTH 로그)는 Unit D의
        // InternalApiKeyFilterTest 에서 별도로 검증한다.
        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.POLICY_REQUEST
                && l.getActionId() == ActorType.GATEWAY && l.isSuccess());
    }

    @Test
    void gatewayActive_whenNothingActive_returns404_andFailureAuditLog() throws Exception {
        policyRepository.deleteAll();
        auditLogRepository.deleteAll();

        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isNotFound());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.POLICY_REQUEST
                && l.getActionId() == ActorType.GATEWAY && !l.isSuccess());
    }

    private Long createPolicy(String name) throws Exception {
        Map<String, Object> body = Map.of(
                "name", name,
                "description", "",
                "l1Enabled", true, "l2Enabled", true, "l3Enabled", true,
                "l4Enabled", true, "l5Enabled", true, "l6Enabled", true
        );
        String response = mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andReturn().getResponse().getContentAsString();
        return ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();
    }
}
