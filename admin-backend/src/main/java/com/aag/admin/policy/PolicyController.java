package com.aag.admin.policy;

import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLogService;
import com.aag.admin.common.NotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Tag(name = "Policy", description = "L1~L6 가드레일 정책 관리 API")
@RestController
@RequestMapping("/api/v1/policies")
public class PolicyController {

    private final PolicyRepository repository;
    private final AuditLogService auditLogService;

    public PolicyController(PolicyRepository repository, AuditLogService auditLogService) {
        this.repository = repository;
        this.auditLogService = auditLogService;
    }

    @Operation(summary = "정책 생성", description = "관리자(ADMIN) 전용")
    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@Valid @RequestBody PolicyRequest request) {
        Policy policy = new Policy();
        applyRequest(policy, request);
        policy.setUse(false);
        Policy saved = repository.save(policy);
        auditLogService.record(ActorType.ADMIN, Action.POLICY_CREATE, true, policyDetail(saved));
        return ResponseEntity.created(URI.create("/api/v1/policies/" + saved.getId()))
                .body(toResponse(saved));
    }

    @Operation(summary = "정책 목록 조회")
    @GetMapping
    public List<Map<String, Object>> list() {
        return repository.findAllByOrderByCreatedAtAsc().stream()
                .map(this::toResponse)
                .toList();
    }

    @Operation(summary = "정책 단건 조회")
    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable Long id) {
        Policy policy = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("policy not found: " + id));
        return toResponse(policy);
    }

    @Operation(summary = "정책 수정", description = "관리자(ADMIN) 전용")
    @PutMapping("/{id}")
    public Map<String, Object> update(@PathVariable Long id, @Valid @RequestBody PolicyRequest request) {
        Policy policy = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("policy not found: " + id));
        applyRequest(policy, request);
        policy.setUpdatedAt(Instant.now());
        Policy saved = repository.save(policy);
        auditLogService.record(ActorType.ADMIN, Action.POLICY_UPDATE, true, policyDetail(saved));
        return toResponse(saved);
    }

    @Operation(summary = "정책 활성화", description = "다른 활성 정책은 자동 비활성화됩니다")
    @PostMapping("/{id}/activate")
    @Transactional
    public Map<String, Object> activate(@PathVariable Long id) {
        Policy policy = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("policy not found: " + id));
        repository.clearActiveExcept(id);
        policy.setUse(true);
        policy.setUpdatedAt(Instant.now());
        Policy saved = repository.save(policy);
        auditLogService.record(ActorType.ADMIN, Action.POLICY_ACTIVATE, true, policyDetail(saved));
        return toResponse(saved);
    }

    @Operation(summary = "정책 삭제")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        Policy policy = repository.findById(id)
                .orElseThrow(() -> new NotFoundException("policy not found: " + id));
        String detail = policyDetail(policy);
        repository.delete(policy);
        auditLogService.record(ActorType.ADMIN, Action.POLICY_DELETE, true, detail);
        return ResponseEntity.noContent().build();
    }

    private void applyRequest(Policy policy, PolicyRequest request) {
        policy.setName(request.getName());
        policy.setDescription(request.getDescription());
        policy.setL1Enabled(request.isL1Enabled());
        policy.setL2Enabled(request.isL2Enabled());
        policy.setL3Enabled(request.isL3Enabled());
        policy.setL4Enabled(request.isL4Enabled());
        policy.setL5Enabled(request.isL5Enabled());
        policy.setL6Enabled(request.isL6Enabled());
    }

    private String policyDetail(Policy policy) {
        return "id=" + policy.getId() + ", name=" + policy.getName();
    }

    private Map<String, Object> toResponse(Policy policy) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", policy.getId());
        map.put("name", policy.getName());
        map.put("description", policy.getDescription());
        map.put("isUse", policy.isUse());
        map.put("l1Enabled", policy.isL1Enabled());
        map.put("l2Enabled", policy.isL2Enabled());
        map.put("l3Enabled", policy.isL3Enabled());
        map.put("l4Enabled", policy.isL4Enabled());
        map.put("l5Enabled", policy.isL5Enabled());
        map.put("l6Enabled", policy.isL6Enabled());
        map.put("createdAt", policy.getCreatedAt());
        map.put("updatedAt", policy.getUpdatedAt());
        return map;
    }
}
