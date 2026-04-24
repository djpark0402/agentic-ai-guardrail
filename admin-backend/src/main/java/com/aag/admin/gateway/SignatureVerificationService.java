package com.aag.admin.gateway;

import com.aag.admin.agentkey.AgentApiKey;
import com.aag.admin.agentkey.AgentApiKeyService;
import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLogService;
import com.aag.admin.policy.Policy;
import com.aag.admin.policy.PolicyRepository;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Optional;

@Service
public class SignatureVerificationService {

    private static final long TIMESTAMP_SKEW_SECONDS = 300;

    private final AgentApiKeyService agentKeyService;
    private final PolicyRepository policyRepository;
    private final AuditLogService auditLogService;

    public SignatureVerificationService(AgentApiKeyService agentKeyService,
                                        PolicyRepository policyRepository,
                                        AuditLogService auditLogService) {
        this.agentKeyService = agentKeyService;
        this.policyRepository = policyRepository;
        this.auditLogService = auditLogService;
    }

    public Result verify(VerifyRequest req) {
        long ts;
        try {
            ts = Long.parseLong(req.getTimestamp());
        } catch (NumberFormatException ex) {
            return failure("timestamp_skew", req.getApiKey());
        }
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - ts) > TIMESTAMP_SKEW_SECONDS) {
            return failure("timestamp_skew", req.getApiKey());
        }

        Optional<AgentApiKey> keyOpt = agentKeyService.findActiveByApiKey(req.getApiKey());
        if (keyOpt.isEmpty()) {
            String reason = classifyMissing(req.getApiKey());
            return failure(reason, req.getApiKey());
        }
        AgentApiKey key = keyOpt.get();

        String secret = agentKeyService.decryptSecret(key);

        String canonical = req.getTimestamp() + "." + req.getNonce() + "." + req.getBodyHash();
        String expected = hmacSha256Hex(secret, canonical);
        if (!constantTimeEquals(expected, req.getSignature())) {
            return failure("invalid_signature", key);
        }

        Optional<Policy> policyOpt = policyRepository.findByIsUseTrue();
        if (policyOpt.isEmpty()) {
            return failure("no_active_policy", key);
        }

        agentKeyService.touchLastUsed(key);
        auditLogService.record(ActorType.GATEWAY, Action.AGENT_AUTH, true,
                "clientName=" + key.getClientName() + ", agentKeyId=" + key.getId());

        return Result.success(key, policyOpt.get());
    }

    private String classifyMissing(String plainApiKey) {
        Optional<AgentApiKey> raw = agentKeyService.findRawByApiKey(plainApiKey);
        if (raw.isEmpty()) return "unknown_key";
        AgentApiKey k = raw.get();
        if (k.getRevokedAt() != null) return "revoked";
        return "expired";
    }

    private Result failure(String reason, String plainApiKeyForLog) {
        String prefix = plainApiKeyForLog == null || plainApiKeyForLog.length() < 12
                ? String.valueOf(plainApiKeyForLog) : plainApiKeyForLog.substring(0, 12);
        auditLogService.record(ActorType.GATEWAY, Action.AGENT_AUTH, false,
                "reason=" + reason + ", apiKeyPrefix=" + prefix);
        return Result.failure(reason);
    }

    private Result failure(String reason, AgentApiKey key) {
        auditLogService.record(ActorType.GATEWAY, Action.AGENT_AUTH, false,
                "reason=" + reason + ", apiKeyPrefix=" + key.getKeyPrefix() + ", clientName=" + key.getClientName());
        return Result.failure(reason);
    }

    private static String hmacSha256Hex(String secret, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] out = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception ex) {
            throw new IllegalStateException("HMAC-SHA256 failed", ex);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    public sealed interface Result {
        static Result success(AgentApiKey key, Policy policy) { return new Success(key, policy); }
        static Result failure(String reason) { return new Failure(reason); }

        record Success(AgentApiKey key, Policy policy) implements Result {}
        record Failure(String reason) implements Result {}
    }
}
