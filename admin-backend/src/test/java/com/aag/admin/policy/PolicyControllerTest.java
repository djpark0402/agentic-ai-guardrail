package com.aag.admin.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

import java.util.Map;

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

    @Test
    void createPolicy_returns201_withLocation() throws Exception {
        Map<String, Object> body = Map.of(
                "name", "block-pii",
                "description", "Block PII leakage",
                "ruleType", "REGEX",
                "pattern", "\\d{3}-\\d{2}-\\d{4}",
                "enabled", true
        );

        mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.name").value("block-pii"));
    }

    @Test
    void createPolicy_withInvalidBody_returns400() throws Exception {
        Map<String, Object> body = Map.of("description", "missing name");

        mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void listPolicies_returnsPagedResult() throws Exception {
        mockMvc.perform(get("/api/v1/policies").param("page", "0").param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray());
    }

    @Test
    void getPolicy_whenNotFound_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/policies/{id}", 99999))
                .andExpect(status().isNotFound());
    }

    @Test
    void updatePolicy_returns200() throws Exception {
        Map<String, Object> create = Map.of(
                "name", "update-target",
                "description", "d",
                "ruleType", "REGEX",
                "pattern", ".*",
                "enabled", true
        );
        String response = mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(create)))
                .andReturn().getResponse().getContentAsString();
        Long id = ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();

        Map<String, Object> update = Map.of(
                "name", "update-target",
                "description", "updated",
                "ruleType", "REGEX",
                "pattern", ".*",
                "enabled", false
        );
        mockMvc.perform(put("/api/v1/policies/{id}", id)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(update)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));
    }

    @Test
    void deletePolicy_returns204() throws Exception {
        Map<String, Object> create = Map.of(
                "name", "delete-target",
                "description", "d",
                "ruleType", "REGEX",
                "pattern", ".*",
                "enabled", true
        );
        String response = mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(create)))
                .andReturn().getResponse().getContentAsString();
        Long id = ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();

        mockMvc.perform(delete("/api/v1/policies/{id}", id))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/policies/{id}", id))
                .andExpect(status().isNotFound());
    }
}
