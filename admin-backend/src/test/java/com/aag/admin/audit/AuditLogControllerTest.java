package com.aag.admin.audit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuditLogControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void listAuditLogs_returnsPagedResult() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs")
                        .param("page", "0")
                        .param("size", "20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray());
    }

    @Test
    void listAuditLogs_withDateRangeFilter_returnsOk() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs")
                        .param("from", "2026-01-01T00:00:00Z")
                        .param("to", "2026-12-31T23:59:59Z"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray());
    }

    @Test
    void listAuditLogs_withInvalidDateRange_returns400() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs")
                        .param("from", "2026-12-31T00:00:00Z")
                        .param("to", "2026-01-01T00:00:00Z"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getAuditLog_whenNotFound_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/audit-logs/{id}", 999999))
                .andExpect(status().isNotFound());
    }
}
