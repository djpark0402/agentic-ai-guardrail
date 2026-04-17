package com.aag.admin.policy;

import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLogService;
import com.aag.admin.common.NotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Tag(name = "Gateway", description = "Gateway 서버 전용 엔드포인트 (X-API-Key 필수)")
@RestController
@RequestMapping("/api/v1/gateway")
public class GatewayPolicyController {

    private final PolicyRepository policyRepository;
    private final AuditLogService auditLogService;

    public GatewayPolicyController(PolicyRepository policyRepository, AuditLogService auditLogService) {
        this.policyRepository = policyRepository;
        this.auditLogService = auditLogService;
    }

    @Operation(summary = "현재 활성 정책 조회", description = "is_use=true 인 정책 1건을 반환합니다. 활성 정책이 없으면 404.")
    @GetMapping("/policies/active")
    public Map<String, Object> active() {
        Optional<Policy> policyOpt = policyRepository.findByIsUseTrue();
        if (policyOpt.isEmpty()) {
            auditLogService.record(ActorType.GATEWAY, Action.POLICY_REQUEST, false, "no active policy");
            throw new NotFoundException("no active policy");
        }
        Policy policy = policyOpt.get();
        auditLogService.record(ActorType.GATEWAY, Action.POLICY_REQUEST, true,
                "id=" + policy.getId() + ", name=" + policy.getName());
        return toResponse(policy);
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
