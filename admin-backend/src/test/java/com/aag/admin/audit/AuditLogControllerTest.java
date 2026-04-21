package com.aag.admin.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuditLogControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AuditLogRepository repository;

    @BeforeEach
    void seed() {
        repository.deleteAll();
        repository.save(build(Instant.now().minus(2, ChronoUnit.HOURS), ActorType.ADMIN, Action.POLICY_CREATE, true));
        repository.save(build(Instant.now().minus(1, ChronoUnit.HOURS), ActorType.GATEWAY, Action.POLICY_REQUEST, true));
        repository.save(build(Instant.now(), ActorType.GATEWAY, Action.POLICY_REQUEST, false));
    }

    @Test
    void listAuditLogs_returnsPagedResult() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs").param("page", "0").param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.totalElements").value(3));
    }

    @Test
    void listAuditLogs_filterByActionId() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs").param("actionId", "GATEWAY"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    void listAuditLogs_filterBySuccess() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs").param("success", "false"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    void listAuditLogs_filterByAction() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs").param("action", "POLICY_CREATE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1));
    }

    @Test
    void listAuditLogs_withInvalidDateRange_returns400() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs")
                        .param("from", "2026-12-31T00:00:00Z")
                        .param("to", "2026-01-01T00:00:00Z"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void listAuditLogs_withInvalidActionId_returns400() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs").param("actionId", "UNKNOWN"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void listAuditLogs_sortByOccurredAtAsc() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs")
                        .param("sort", "occurredAt")
                        .param("direction", "asc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].action").value("POLICY_CREATE"));
    }

    @Test
    void getAuditLog_whenNotFound_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs/{id}", 999999))
                .andExpect(status().isNotFound());
    }

    private AuditLog build(Instant at, ActorType actor, Action action, boolean success) {
        AuditLog log = new AuditLog();
        log.setOccurredAt(at);
        log.setActionId(actor);
        log.setAction(action);
        log.setSuccess(success);
        return log;
    }
}
