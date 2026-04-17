package com.aag.admin.policy;

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
class PolicyControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    PolicyRepository repository;

    @Autowired
    AuditLogRepository auditLogRepository;

    @BeforeEach
    void cleanDb() {
        auditLogRepository.deleteAll();
        repository.deleteAll();
    }

    @Test
    void createPolicy_returns201_writesAuditLog() throws Exception {
        Map<String, Object> body = Map.of(
                "name", "default-strict",
                "description", "기본 엄격",
                "l1Enabled", true,
                "l2Enabled", true,
                "l3Enabled", false,
                "l4Enabled", false,
                "l5Enabled", true,
                "l6Enabled", true
        );

        mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.name").value("default-strict"))
                .andExpect(jsonPath("$.isUse").value(false));

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getActionId()).isEqualTo(ActorType.ADMIN);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.POLICY_CREATE);
        assertThat(logs.get(0).isSuccess()).isTrue();
        assertThat(logs.get(0).getDetail()).contains("name=default-strict");
    }

    @Test
    void createPolicy_withInvalidBody_returns400() throws Exception {
        Map<String, Object> body = Map.of("description", "missing name");

        mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        assertThat(auditLogRepository.count()).isZero();
    }

    @Test
    void listPolicies_returnsArray() throws Exception {
        mockMvc.perform(get("/api/v1/policies"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void getPolicy_whenNotFound_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/policies/{id}", 99999))
                .andExpect(status().isNotFound());
    }

    @Test
    void updatePolicy_writesAuditLog() throws Exception {
        Long id = createPolicy("target", true, true, true, true, true, true);
        auditLogRepository.deleteAll();

        Map<String, Object> update = Map.of(
                "name", "target",
                "description", "updated",
                "l1Enabled", false,
                "l2Enabled", false,
                "l3Enabled", true,
                "l4Enabled", true,
                "l5Enabled", false,
                "l6Enabled", false
        );
        mockMvc.perform(put("/api/v1/policies/{id}", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(update)))
                .andExpect(status().isOk());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.POLICY_UPDATE);
        assertThat(logs.get(0).getActionId()).isEqualTo(ActorType.ADMIN);
    }

    @Test
    void activatePolicy_writesAuditLog_andSwitchesActive() throws Exception {
        Long first = createPolicy("first", true, false, false, false, false, false);
        Long second = createPolicy("second", false, true, false, false, false, false);
        auditLogRepository.deleteAll();

        mockMvc.perform(post("/api/v1/policies/{id}/activate", first))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isUse").value(true));

        mockMvc.perform(post("/api/v1/policies/{id}/activate", second))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isUse").value(true));

        mockMvc.perform(get("/api/v1/policies/{id}", first))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isUse").value(false));

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(2);
        assertThat(logs).allMatch(l -> l.getAction() == Action.POLICY_ACTIVATE && l.getActionId() == ActorType.ADMIN);
    }

    @Test
    void deletePolicy_writesAuditLog() throws Exception {
        Long id = createPolicy("delete-target", true, true, true, true, true, true);
        auditLogRepository.deleteAll();

        mockMvc.perform(delete("/api/v1/policies/{id}", id))
                .andExpect(status().isNoContent());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.POLICY_DELETE);
    }

    private Long createPolicy(String name, boolean l1, boolean l2, boolean l3, boolean l4, boolean l5, boolean l6) throws Exception {
        Map<String, Object> body = Map.of(
                "name", name,
                "description", "",
                "l1Enabled", l1,
                "l2Enabled", l2,
                "l3Enabled", l3,
                "l4Enabled", l4,
                "l5Enabled", l5,
                "l6Enabled", l6
        );
        String response = mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andReturn().getResponse().getContentAsString();
        return ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();
    }
}
