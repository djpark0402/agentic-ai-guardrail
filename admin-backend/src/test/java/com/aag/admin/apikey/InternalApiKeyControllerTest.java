package com.aag.admin.apikey;

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
class InternalApiKeyControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired InternalApiKeyRepository repository;
    @Autowired AuditLogRepository auditLogRepository;

    @BeforeEach
    void cleanDb() {
        auditLogRepository.deleteAll();
        repository.deleteAll();
    }

    @Test
    void createKey_returns201_withPlainKey_andWritesAudit() throws Exception {
        Map<String, Object> body = Map.of("name", "gw-prod-01", "description", "운영 Gateway");

        String response = mockMvc.perform(post("/api/v1/internal-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.name").value("gw-prod-01"))
                .andExpect(jsonPath("$.plainKey").isString())
                .andExpect(jsonPath("$.keyPrefix").isString())
                .andExpect(jsonPath("$.keyHash").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        String plainKey = (String) objectMapper.readValue(response, Map.class).get("plainKey");
        assertThat(plainKey).startsWith("iak_");
        assertThat(plainKey).hasSize(36);

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.APIKEY_CREATE);
        assertThat(logs.get(0).getActionId()).isEqualTo(ActorType.ADMIN);
        assertThat(logs.get(0).isSuccess()).isTrue();
    }

    @Test
    void createKey_withBlankName_returns400() throws Exception {
        Map<String, Object> body = Map.of("name", "");

        mockMvc.perform(post("/api/v1/internal-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        assertThat(auditLogRepository.count()).isZero();
    }

    @Test
    void createKey_withPastExpiresAt_returns400() throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("name", "past");
        body.put("expiresAt", Instant.now().minus(1, ChronoUnit.DAYS).toString());

        mockMvc.perform(post("/api/v1/internal-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void listKeys_neverIncludesPlainKeyOrHash() throws Exception {
        Map<String, Object> body = Map.of("name", "k1");
        mockMvc.perform(post("/api/v1/internal-api-keys")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)));

        mockMvc.perform(get("/api/v1/internal-api-keys"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].plainKey").doesNotExist())
                .andExpect(jsonPath("$[0].keyHash").doesNotExist())
                .andExpect(jsonPath("$[0].keyPrefix").isString());
    }

    @Test
    void getKey_whenNotFound_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/internal-api-keys/{id}", 99999))
                .andExpect(status().isNotFound());
    }

    @Test
    void revokeKey_setsRevokedAt_andWritesAudit() throws Exception {
        Long id = createKey("to-revoke");
        auditLogRepository.deleteAll();

        mockMvc.perform(post("/api/v1/internal-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedAt").isString());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.APIKEY_REVOKE);
    }

    @Test
    void revokeKey_isIdempotent() throws Exception {
        Long id = createKey("two-revokes");

        String first = mockMvc.perform(post("/api/v1/internal-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String second = mockMvc.perform(post("/api/v1/internal-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Object firstAt = objectMapper.readValue(first, Map.class).get("revokedAt");
        Object secondAt = objectMapper.readValue(second, Map.class).get("revokedAt");
        assertThat(firstAt).isEqualTo(secondAt);
    }

    private Long createKey(String name) throws Exception {
        Map<String, Object> body = Map.of("name", name);
        String response = mockMvc.perform(post("/api/v1/internal-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andReturn().getResponse().getContentAsString();
        return ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();
    }
}
