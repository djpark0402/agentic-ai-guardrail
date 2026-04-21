package com.aag.admin.apikey;

import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLogService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

public class InternalApiKeyFilter extends OncePerRequestFilter {

    private static final String HEADER = "X-API-Key";
    private static final String PATH_PATTERN = "/api/v1/gateway/**";
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    private final InternalApiKeyService service;
    private final AuditLogService auditLogService;

    public InternalApiKeyFilter(InternalApiKeyService service, AuditLogService auditLogService) {
        this.service = service;
        this.auditLogService = auditLogService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !pathMatcher.match(PATH_PATTERN, request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String plainKey = request.getHeader(HEADER);
        if (plainKey == null || plainKey.isEmpty()) {
            auditLogService.record(ActorType.GATEWAY, Action.APIKEY_AUTH, false,
                    "missing X-API-Key header");
            writeUnauthorized(response, "missing X-API-Key header");
            return;
        }

        Optional<InternalApiKey> keyOpt = service.findActiveByPlainKey(plainKey);
        if (keyOpt.isEmpty()) {
            String prefix = plainKey.length() >= 12 ? plainKey.substring(0, 12) : plainKey;
            auditLogService.record(ActorType.GATEWAY, Action.APIKEY_AUTH, false,
                    "invalid key: prefix=" + prefix);
            writeUnauthorized(response, "invalid api key");
            return;
        }

        InternalApiKey key = keyOpt.get();
        service.touchLastUsed(key);
        auditLogService.record(ActorType.GATEWAY, Action.APIKEY_AUTH, true,
                "keyPrefix=" + key.getKeyPrefix() + ", name=" + key.getName());
        chain.doFilter(request, response);
    }

    private void writeUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"error\":\"unauthorized\",\"message\":\"" + message + "\"}");
    }
}
