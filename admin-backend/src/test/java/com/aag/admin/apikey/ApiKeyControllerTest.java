package com.aag.admin.apikey;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApiKeyControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    void issueApiKey_returnsPlainKeyOnce() throws Exception {
        Map<String, Object> body = Map.of(
                "name", "gateway-key",
                "owner", "guardrail-backend"
        );

        mockMvc.perform(post("/api/v1/api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.plainKey").isString())
                .andExpect(jsonPath("$.keyHash").doesNotExist());
    }

    @Test
    void listApiKeys_neverIncludesPlainKey() throws Exception {
        mockMvc.perform(get("/api/v1/api-keys"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].plainKey").doesNotExist());
    }

    @Test
    void revokeApiKey_returns204_andMarksRevoked() throws Exception {
        Map<String, Object> body = Map.of("name", "temp", "owner", "svc");
        String response = mockMvc.perform(post("/api/v1/api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andReturn().getResponse().getContentAsString();
        Long id = ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();

        mockMvc.perform(delete("/api/v1/api-keys/{id}", id))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/api-keys/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revoked").value(true));
    }

    @Test
    void issueApiKey_withBlankName_returns400() throws Exception {
        Map<String, Object> body = Map.of("name", "", "owner", "svc");

        mockMvc.perform(post("/api/v1/api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }
}
