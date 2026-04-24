package com.aag.admin.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI raonGuardrailOpenAPI() {
        return new OpenAPI()
                .servers(List.of(new Server().url("/").description("Same-origin (reverse proxy)")))
                .info(new Info()
                        .title("라온 가드레일 Admin API")
                        .description("Agentic AI Guardrail 관리자 백엔드 API 문서")
                        .version("v1"));
    }
}
