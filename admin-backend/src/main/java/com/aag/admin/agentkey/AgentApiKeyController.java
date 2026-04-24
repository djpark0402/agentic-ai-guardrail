package com.aag.admin.agentkey;

import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLogService;
import com.aag.admin.common.BadRequestException;
import com.aag.admin.common.NotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Tag(name = "Agent API Key", description = "외부 Agent용 API 키 + Secret 관리")
@RestController
@RequestMapping("/api/v1/agent-api-keys")
public class AgentApiKeyController {

    private final AgentApiKeyRepository repository;
    private final AgentApiKeyService service;
    private final AuditLogService auditLogService;

    public AgentApiKeyController(AgentApiKeyRepository repository,
                                 AgentApiKeyService service,
                                 AuditLogService auditLogService) {
        this.repository = repository;
        this.service = service;
        this.auditLogService = auditLogService;
    }

    @Operation(summary = "Agent API 키 발급", description = "apiKey, secret은 이 응답에만 포함됩니다.")
    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@Valid @RequestBody AgentApiKeyRequest request) {
        if (request.getExpiresAt() != null && !request.getExpiresAt().isAfter(Instant.now())) {
            throw new BadRequestException("expiresAt must be in the future");
        }
        AgentApiKeyService.Issued issued = service.create(request);
        auditLogService.record(ActorType.ADMIN, Action.AGENT_KEY_CREATE, true, detail(issued.entity()));
        Map<String, Object> body = toResponse(issued.entity());
        body.put("apiKey", issued.plainApiKey());
        body.put("secret", issued.plainSecret());
        return ResponseEntity.created(URI.create("/api/v1/agent-api-keys/" + issued.entity().getId()))
                .body(body);
    }

    @Operation(summary = "Agent API 키 목록")
    @GetMapping
    public List<Map<String, Object>> list() {
        return repository.findAllByOrderByCreatedAtDesc().stream()
                .map(this::toResponse)
                .toList();
    }

    @Operation(summary = "Agent API 키 단건")
    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable Long id) {
        return toResponse(findOrThrow(id));
    }

    @Operation(summary = "Agent API 키 폐기 (멱등)")
    @PostMapping("/{id}/revoke")
    public Map<String, Object> revoke(@PathVariable Long id) {
        AgentApiKey key = findOrThrow(id);
        boolean wasActive = key.getRevokedAt() == null;
        AgentApiKey saved = service.revoke(key);
        if (wasActive) {
            auditLogService.record(ActorType.ADMIN, Action.AGENT_KEY_REVOKE, true, detail(saved));
        }
        return toResponse(saved);
    }

    private AgentApiKey findOrThrow(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new NotFoundException("agent api key not found: " + id));
    }

    private String detail(AgentApiKey key) {
        return "id=" + key.getId() + ", clientName=" + key.getClientName() + ", keyPrefix=" + key.getKeyPrefix();
    }

    private Map<String, Object> toResponse(AgentApiKey key) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", key.getId());
        map.put("clientName", key.getClientName());
        map.put("description", key.getDescription());
        map.put("keyPrefix", key.getKeyPrefix());
        map.put("expiresAt", key.getExpiresAt());
        map.put("revokedAt", key.getRevokedAt());
        map.put("lastUsedAt", key.getLastUsedAt());
        map.put("createdAt", key.getCreatedAt());
        map.put("updatedAt", key.getUpdatedAt());
        return map;
    }
}
