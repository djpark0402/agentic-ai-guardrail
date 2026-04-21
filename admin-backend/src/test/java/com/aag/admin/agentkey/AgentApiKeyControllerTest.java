package com.aag.admin.agentkey;

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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AgentApiKeyControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired AgentApiKeyRepository repository;
    @Autowired AuditLogRepository auditLogRepository;

    @BeforeEach
    void cleanDb() {
        auditLogRepository.deleteAll();
        repository.deleteAll();
    }

    @Test
    void createKey_returns201_withApiKeyAndSecret_andWritesAudit() throws Exception {
        Map<String, Object> body = Map.of("clientName", "고객사A", "description", "운영");

        String response = mockMvc.perform(post("/api/v1/agent-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.clientName").value("고객사A"))
                .andExpect(jsonPath("$.apiKey").isString())
                .andExpect(jsonPath("$.secret").isString())
                .andExpect(jsonPath("$.keyPrefix").isString())
                .andExpect(jsonPath("$.apiKeyHash").doesNotExist())
                .andExpect(jsonPath("$.secretEncrypted").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> json = objectMapper.readValue(response, Map.class);
        String apiKey = (String) json.get("apiKey");
        String secret = (String) json.get("secret");
        String prefix = (String) json.get("keyPrefix");

        assertThat(apiKey).startsWith("ak_").hasSize(35);
        assertThat(secret).hasSize(43);
        assertThat(prefix).startsWith("ak_").hasSize(12);
        assertThat(apiKey).startsWith(prefix);

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.AGENT_KEY_CREATE);
        assertThat(logs.get(0).getActionId()).isEqualTo(ActorType.ADMIN);
        assertThat(logs.get(0).isSuccess()).isTrue();
        assertThat(logs.get(0).getDetail()).contains("clientName=고객사A");
    }

    @Test
    void createKey_withBlankClientName_returns400() throws Exception {
        Map<String, Object> body = Map.of("clientName", "");

        mockMvc.perform(post("/api/v1/agent-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        assertThat(auditLogRepository.count()).isZero();
    }

    @Test
    void createKey_withPastExpiresAt_returns400() throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("clientName", "past");
        body.put("expiresAt", Instant.now().minus(1, ChronoUnit.DAYS).toString());

        mockMvc.perform(post("/api/v1/agent-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void listKeys_neverIncludesApiKeyOrSecretOrHash() throws Exception {
        Map<String, Object> body = Map.of("clientName", "list-test");
        mockMvc.perform(post("/api/v1/agent-api-keys")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)));

        mockMvc.perform(get("/api/v1/agent-api-keys"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].apiKey").doesNotExist())
                .andExpect(jsonPath("$[0].apiKeyHash").doesNotExist())
                .andExpect(jsonPath("$[0].secret").doesNotExist())
                .andExpect(jsonPath("$[0].secretEncrypted").doesNotExist())
                .andExpect(jsonPath("$[0].keyPrefix").isString());
    }

    @Test
    void getKey_whenNotFound_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/agent-api-keys/{id}", 99999))
                .andExpect(status().isNotFound());
    }

    @Test
    void revokeKey_setsRevokedAt_andWritesAudit() throws Exception {
        Long id = createKey("to-revoke");
        auditLogRepository.deleteAll();

        mockMvc.perform(post("/api/v1/agent-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedAt").isString());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.AGENT_KEY_REVOKE);
    }

    @Test
    void revokeKey_isIdempotent() throws Exception {
        Long id = createKey("two-revokes");

        String first = mockMvc.perform(post("/api/v1/agent-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String second = mockMvc.perform(post("/api/v1/agent-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(objectMapper.readValue(first, Map.class).get("revokedAt"))
                .isEqualTo(objectMapper.readValue(second, Map.class).get("revokedAt"));
    }

    private Long createKey(String name) throws Exception {
        Map<String, Object> body = Map.of("clientName", name);
        String response = mockMvc.perform(post("/api/v1/agent-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andReturn().getResponse().getContentAsString();
        return ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();
    }
}
