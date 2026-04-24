package com.aag.admin.config;

import com.aag.admin.apikey.InternalApiKeyFilter;
import com.aag.admin.apikey.InternalApiKeyService;
import com.aag.admin.audit.AuditLogService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http,
                                    InternalApiKeyService apiKeyService,
                                    AuditLogService auditLogService) throws Exception {
        InternalApiKeyFilter apiKeyFilter = new InternalApiKeyFilter(apiKeyService, auditLogService);
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(apiKeyFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
