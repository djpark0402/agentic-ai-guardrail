package com.aag.admin.apikey;

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
public class InternalApiKeyService {

    private static final String KEY_PREFIX = "iak_";
    private static final int RANDOM_BYTES = 24;
    private static final int PREFIX_LENGTH = 12;

    private final InternalApiKeyRepository repository;
    private final SecureRandom random = new SecureRandom();

    public InternalApiKeyService(InternalApiKeyRepository repository) {
        this.repository = repository;
    }

    /** 평문 키 생성 → 엔티티 저장 → (엔티티, 평문) 반환. 평문은 이 시점에만 접근 가능. */
    @Transactional
    public Issued create(InternalApiKeyRequest request) {
        byte[] bytes = new byte[RANDOM_BYTES];
        random.nextBytes(bytes);
        String plainKey = KEY_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        InternalApiKey entity = new InternalApiKey();
        entity.setName(request.getName());
        entity.setDescription(request.getDescription());
        entity.setExpiresAt(request.getExpiresAt());
        entity.setKeyPrefix(plainKey.substring(0, PREFIX_LENGTH));
        entity.setKeyHash(sha256Hex(plainKey));
        InternalApiKey saved = repository.save(entity);
        return new Issued(saved, plainKey);
    }

    /** 평문 키를 해시해 DB 조회. 활성(revoked_at null, 만료 전)만 반환. */
    @Transactional
    public Optional<InternalApiKey> findActiveByPlainKey(String plainKey) {
        if (plainKey == null || plainKey.isEmpty()) {
            return Optional.empty();
        }
        return repository.findByKeyHash(sha256Hex(plainKey))
                .filter(this::isActive);
    }

    @Transactional
    public void touchLastUsed(InternalApiKey key) {
        key.setLastUsedAt(Instant.now());
        repository.save(key);
    }

    /** 이미 폐기되었으면 기존 revokedAt 유지 (idempotent). */
    @Transactional
    public InternalApiKey revoke(InternalApiKey key) {
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

    private boolean isActive(InternalApiKey key) {
        if (key.getRevokedAt() != null) return false;
        if (key.getExpiresAt() != null && !key.getExpiresAt().isAfter(Instant.now())) return false;
        return true;
    }

    public record Issued(InternalApiKey entity, String plainKey) {}
}
