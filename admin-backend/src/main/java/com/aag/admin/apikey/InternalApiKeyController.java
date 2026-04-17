package com.aag.admin.apikey;

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

@Tag(name = "Internal API Key", description = "Admin↔Gateway 내부 인증용 API 키 관리")
@RestController
@RequestMapping("/api/v1/internal-api-keys")
public class InternalApiKeyController {

    private final InternalApiKeyRepository repository;
    private final InternalApiKeyService service;
    private final AuditLogService auditLogService;

    public InternalApiKeyController(InternalApiKeyRepository repository,
                                    InternalApiKeyService service,
                                    AuditLogService auditLogService) {
        this.repository = repository;
        this.service = service;
        this.auditLogService = auditLogService;
    }

    @Operation(summary = "API 키 발급", description = "평문 키는 이 응답에만 포함됩니다.")
    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@Valid @RequestBody InternalApiKeyRequest request) {
        if (request.getExpiresAt() != null && !request.getExpiresAt().isAfter(Instant.now())) {
            throw new BadRequestException("expiresAt must be in the future");
        }
        InternalApiKeyService.Issued issued = service.create(request);
        auditLogService.record(ActorType.ADMIN, Action.APIKEY_CREATE, true, detail(issued.entity()));
        Map<String, Object> body = toResponse(issued.entity());
        body.put("plainKey", issued.plainKey());
        return ResponseEntity.created(URI.create("/api/v1/internal-api-keys/" + issued.entity().getId()))
                .body(body);
    }

    @Operation(summary = "API 키 목록")
    @GetMapping
    public List<Map<String, Object>> list() {
        return repository.findAllByOrderByCreatedAtDesc().stream()
                .map(this::toResponse)
                .toList();
    }

    @Operation(summary = "API 키 단건")
    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable Long id) {
        return toResponse(findOrThrow(id));
    }

    @Operation(summary = "API 키 폐기 (멱등)")
    @PostMapping("/{id}/revoke")
    public Map<String, Object> revoke(@PathVariable Long id) {
        InternalApiKey key = findOrThrow(id);
        boolean wasActive = key.getRevokedAt() == null;
        InternalApiKey saved = service.revoke(key);
        if (wasActive) {
            auditLogService.record(ActorType.ADMIN, Action.APIKEY_REVOKE, true, detail(saved));
        }
        return toResponse(saved);
    }

    private InternalApiKey findOrThrow(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new NotFoundException("internal api key not found: " + id));
    }

    private String detail(InternalApiKey key) {
        return "id=" + key.getId() + ", name=" + key.getName() + ", keyPrefix=" + key.getKeyPrefix();
    }

    private Map<String, Object> toResponse(InternalApiKey key) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", key.getId());
        map.put("name", key.getName());
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
