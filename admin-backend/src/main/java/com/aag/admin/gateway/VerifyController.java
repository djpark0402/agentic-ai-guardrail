package com.aag.admin.gateway;

import com.aag.admin.policy.Policy;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@Tag(name = "Gateway", description = "Gateway 전용 — 서명 검증 + 활성 정책 통합 응답")
@RestController
@RequestMapping("/api/v1/gateway")
public class VerifyController {

    private final SignatureVerificationService verificationService;

    public VerifyController(SignatureVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @Operation(summary = "Agent 서명 검증 + 활성 정책 조회",
               description = "유효 시 valid:true + clientName + agentKeyId + policy 함께 응답.")
    @PostMapping("/verify")
    public Map<String, Object> verify(@Valid @RequestBody VerifyRequest request) {
        SignatureVerificationService.Result result = verificationService.verify(request);
        Map<String, Object> body = new LinkedHashMap<>();
        if (result instanceof SignatureVerificationService.Result.Success s) {
            body.put("valid", true);
            body.put("clientName", s.key().getClientName());
            body.put("agentKeyId", s.key().getId());
            body.put("policy", policyResponse(s.policy()));
        } else if (result instanceof SignatureVerificationService.Result.Failure f) {
            body.put("valid", false);
            body.put("reason", f.reason());
        }
        return body;
    }

    private Map<String, Object> policyResponse(Policy policy) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", policy.getId());
        map.put("name", policy.getName());
        map.put("l1Enabled", policy.isL1Enabled());
        map.put("l2Enabled", policy.isL2Enabled());
        map.put("l3Enabled", policy.isL3Enabled());
        map.put("l4Enabled", policy.isL4Enabled());
        map.put("l5Enabled", policy.isL5Enabled());
        map.put("l6Enabled", policy.isL6Enabled());
        map.put("outboundEnabled", policy.isOutboundEnabled());
        return map;
    }
}
