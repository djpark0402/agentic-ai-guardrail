package com.aag.admin.agentkey;

import com.aag.admin.crypto.SecretCipher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Service
public class AgentApiKeyService {

    private static final String API_KEY_PREFIX = "ak_";
    private static final int API_KEY_RANDOM_BYTES = 24;   // → base64url 32자 → 총 35자
    private static final int SECRET_RANDOM_BYTES = 32;    // → base64url 43자
    private static final int PREFIX_LENGTH = 12;          // "ak_" + 8 random chars

    private final AgentApiKeyRepository repository;
    private final SecretCipher secretCipher;
    private final SecureRandom random = new SecureRandom();

    public AgentApiKeyService(AgentApiKeyRepository repository, SecretCipher secretCipher) {
        this.repository = repository;
        this.secretCipher = secretCipher;
    }

    /** 평문 apiKey + secret 생성 → 암호화/해시 후 저장 → (entity, plainApiKey, plainSecret) 리턴. */
    @Transactional
    public Issued create(AgentApiKeyRequest request) {
        String plainApiKey = generateApiKey();
        String plainSecret = generateSecret();

        AgentApiKey entity = new AgentApiKey();
        entity.setClientName(request.getClientName());
        entity.setDescription(request.getDescription());
        entity.setExpiresAt(request.getExpiresAt());
        entity.setKeyPrefix(plainApiKey.substring(0, PREFIX_LENGTH));
        entity.setApiKeyHash(sha256Hex(plainApiKey));
        entity.setSecretEncrypted(secretCipher.encrypt(plainSecret));
        AgentApiKey saved = repository.save(entity);
        return new Issued(saved, plainApiKey, plainSecret);
    }

    /** 평문 apiKey를 해시해 DB 조회. 활성(revoked 아님 + 만료 전)만 리턴. */
    @Transactional
    public Optional<AgentApiKey> findActiveByApiKey(String plainApiKey) {
        if (plainApiKey == null || plainApiKey.isEmpty()) {
            return Optional.empty();
        }
        return repository.findByApiKeyHash(sha256Hex(plainApiKey))
                .filter(this::isActive);
    }

    /** revoke/만료 여부 무시. unknown vs revoked vs expired 구분용. */
    public Optional<AgentApiKey> findRawByApiKey(String plainApiKey) {
        if (plainApiKey == null || plainApiKey.isEmpty()) {
            return Optional.empty();
        }
        return repository.findByApiKeyHash(sha256Hex(plainApiKey));
    }

    /** secret 평문 복원. 검증 시 호출. */
    public String decryptSecret(AgentApiKey key) {
        return secretCipher.decrypt(key.getSecretEncrypted());
    }

    @Transactional
    public void touchLastUsed(AgentApiKey key) {
        key.setLastUsedAt(Instant.now());
        repository.save(key);
    }

    /** 멱등 — 이미 폐기된 키는 그대로. */
    @Transactional
    public AgentApiKey revoke(AgentApiKey key) {
        if (key.getRevokedAt() == null) {
            Instant now = Instant.now();
            key.setRevokedAt(now);
            key.setUpdatedAt(now);
        }
        return repository.save(key);
    }

    public String sha256Hex(String plain) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(plain.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }

    private String generateApiKey() {
        byte[] bytes = new byte[API_KEY_RANDOM_BYTES];
        random.nextBytes(bytes);
        return API_KEY_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateSecret() {
        byte[] bytes = new byte[SECRET_RANDOM_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private boolean isActive(AgentApiKey key) {
        if (key.getRevokedAt() != null) return false;
        if (key.getExpiresAt() != null && !key.getExpiresAt().isAfter(Instant.now())) return false;
        return true;
    }

    public record Issued(AgentApiKey entity, String plainApiKey, String plainSecret) {}
}
