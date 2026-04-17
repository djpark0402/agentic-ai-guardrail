# Internal API Key Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admin 백엔드에 Internal API Key 발급/폐기/검증 기능을 추가하고, Admin 프론트엔드에 관리 UI를 붙인다. Gateway 전용 엔드포인트(`/api/v1/gateway/**`)는 이 키로 보호한다.

**Architecture:** 1) `InternalApiKey` JPA 엔티티 + 서비스 레이어에서 평문 키 생성·SHA-256 해시 저장·1회 노출. 2) `InternalApiKeyFilter`(OncePerRequestFilter)가 `/api/v1/gateway/**` 요청의 `X-API-Key` 헤더를 DB 해시와 비교해 401 또는 통과, 검증 시마다 `APIKEY_AUTH` 감사 로그 기록. 3) 기존 `GET /api/v1/policies/active`는 `/api/v1/gateway/policies/active`로 이동하여 별도 `GatewayPolicyController`로 분리. 4) 프론트엔드는 `InternalApiKeysPage`를 신규 추가하여 발급/목록/폐기 UI 제공.

**Tech Stack:** Spring Boot 3.2 (Java 17), Spring Security, Spring Data JPA, PostgreSQL, React 18 + TypeScript + Vite, vitest + @testing-library/react.

**Spec:** `docs/superpowers/specs/2026-04-17-internal-api-key-design.md`

---

## File Structure

**Backend 생성**
- `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKey.java` — JPA 엔티티
- `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyRepository.java` — Spring Data 리포지토리
- `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyRequest.java` — 생성 요청 DTO
- `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyService.java` — 평문 키 생성, 해시, 검증 로직
- `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyController.java` — CRUD 엔드포인트
- `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyFilter.java` — Spring Security 필터
- `admin-backend/src/main/java/com/aag/admin/policy/GatewayPolicyController.java` — `/api/v1/gateway/policies/**`

**Backend 수정**
- `admin-backend/src/main/java/com/aag/admin/audit/Action.java` — `APIKEY_CREATE`, `APIKEY_REVOKE`, `APIKEY_AUTH` 추가
- `admin-backend/src/main/java/com/aag/admin/config/SecurityConfig.java` — 필터 체인에 `InternalApiKeyFilter` 등록 (경로 매칭)
- `admin-backend/src/main/java/com/aag/admin/policy/PolicyController.java` — `/active` 엔드포인트 제거
- `admin-backend/src/main/java/com/aag/admin/common/ApiExceptionHandler.java` — 401(Unauthorized) 핸들러 추가

**Backend 테스트 생성**
- `admin-backend/src/test/java/com/aag/admin/apikey/InternalApiKeyControllerTest.java`
- `admin-backend/src/test/java/com/aag/admin/apikey/InternalApiKeyFilterTest.java`
- `admin-backend/src/test/java/com/aag/admin/policy/GatewayPolicyControllerTest.java`

**Backend 테스트 수정**
- `admin-backend/src/test/java/com/aag/admin/policy/PolicyControllerTest.java` — `/active` 관련 테스트 2건 제거

**Frontend 생성**
- `admin-frontend/src/pages/InternalApiKeysPage.tsx`
- `admin-frontend/src/__tests__/InternalApiKeysPage.test.tsx`

**Frontend 수정**
- `admin-frontend/src/App.tsx` — 라우트 + 사이드바 메뉴 추가

---

## Task 1: `Action` enum 확장

**Files:**
- Modify: `admin-backend/src/main/java/com/aag/admin/audit/Action.java`

- [ ] **Step 1: 현재 enum 확인**

현재 내용 (참고):
```java
POLICY_REQUEST("정책 조회"),
POLICY_CREATE("정책 생성"),
POLICY_UPDATE("정책 수정"),
POLICY_DELETE("정책 삭제"),
POLICY_ACTIVATE("정책 활성화");
```

- [ ] **Step 2: 3개 값 추가**

마지막 `POLICY_ACTIVATE(...)` 뒤에 세미콜론을 쉼표로 바꾸고, 다음 3줄을 추가:

```java
POLICY_ACTIVATE("정책 활성화"),
APIKEY_CREATE("내부 API 키 생성"),
APIKEY_REVOKE("내부 API 키 폐기"),
APIKEY_AUTH("Gateway 인증 시도");
```

- [ ] **Step 3: 컴파일 확인**

Run: `cd admin-backend && ./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add admin-backend/src/main/java/com/aag/admin/audit/Action.java
git commit -m "feat: Action enum에 APIKEY_CREATE/REVOKE/AUTH 추가"
```

---

## Task 2: `InternalApiKey` 엔티티 & 리포지토리

**Files:**
- Create: `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKey.java`
- Create: `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyRepository.java`

- [ ] **Step 1: 엔티티 작성**

`admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKey.java`:

```java
package com.aag.admin.apikey;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "internal_api_keys")
public class InternalApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    private String description;

    @Column(name = "key_prefix", nullable = false, length = 12)
    private String keyPrefix;

    @Column(name = "key_hash", nullable = false, unique = true, length = 64)
    private String keyHash;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getKeyPrefix() { return keyPrefix; }
    public void setKeyPrefix(String keyPrefix) { this.keyPrefix = keyPrefix; }
    public String getKeyHash() { return keyHash; }
    public void setKeyHash(String keyHash) { this.keyHash = keyHash; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
    public Instant getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(Instant lastUsedAt) { this.lastUsedAt = lastUsedAt; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
```

- [ ] **Step 2: 리포지토리 작성**

`admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyRepository.java`:

```java
package com.aag.admin.apikey;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface InternalApiKeyRepository extends JpaRepository<InternalApiKey, Long> {

    Optional<InternalApiKey> findByKeyHash(String keyHash);

    List<InternalApiKey> findAllByOrderByCreatedAtDesc();
}
```

- [ ] **Step 3: 컴파일 확인**

Run: `cd admin-backend && ./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKey.java admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyRepository.java
git commit -m "feat: InternalApiKey 엔티티/리포지토리 추가"
```

---

## Task 3: `InternalApiKeyRequest` DTO

**Files:**
- Create: `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyRequest.java`

- [ ] **Step 1: DTO 작성**

```java
package com.aag.admin.apikey;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public class InternalApiKeyRequest {

    @NotBlank
    @Size(max = 100)
    private String name;

    @Size(max = 500)
    private String description;

    private Instant expiresAt;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
}
```

- [ ] **Step 2: Commit**

```bash
git add admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyRequest.java
git commit -m "feat: InternalApiKeyRequest DTO 추가"
```

---

## Task 4: `InternalApiKeyService` — 키 생성·해시·검증

**Files:**
- Create: `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyService.java`

- [ ] **Step 1: 서비스 작성**

```java
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
```

- [ ] **Step 2: 컴파일 확인**

Run: `cd admin-backend && ./gradlew compileJava`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyService.java
git commit -m "feat: InternalApiKeyService — 평문 생성, SHA-256 해시, 활성 검증"
```

---

## Task 5: `InternalApiKeyController` 테스트 먼저 작성 (TDD)

**Files:**
- Create: `admin-backend/src/test/java/com/aag/admin/apikey/InternalApiKeyControllerTest.java`

- [ ] **Step 1: 실패 테스트 작성**

```java
package com.aag.admin.apikey;

import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLog;
import com.aag.admin.audit.AuditLogRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class InternalApiKeyControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired InternalApiKeyRepository repository;
    @Autowired AuditLogRepository auditLogRepository;

    @BeforeEach
    void cleanDb() {
        auditLogRepository.deleteAll();
        repository.deleteAll();
    }

    @Test
    void createKey_returns201_withPlainKey_andWritesAudit() throws Exception {
        Map<String, Object> body = Map.of("name", "gw-prod-01", "description", "운영 Gateway");

        String response = mockMvc.perform(post("/api/v1/internal-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.name").value("gw-prod-01"))
                .andExpect(jsonPath("$.plainKey").isString())
                .andExpect(jsonPath("$.keyPrefix").isString())
                .andExpect(jsonPath("$.keyHash").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        String plainKey = (String) objectMapper.readValue(response, Map.class).get("plainKey");
        assertThat(plainKey).startsWith("iak_");
        assertThat(plainKey).hasSize(36);

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.APIKEY_CREATE);
        assertThat(logs.get(0).getActionId()).isEqualTo(ActorType.ADMIN);
        assertThat(logs.get(0).isSuccess()).isTrue();
    }

    @Test
    void createKey_withBlankName_returns400() throws Exception {
        Map<String, Object> body = Map.of("name", "");

        mockMvc.perform(post("/api/v1/internal-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());

        assertThat(auditLogRepository.count()).isZero();
    }

    @Test
    void createKey_withPastExpiresAt_returns400() throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("name", "past");
        body.put("expiresAt", Instant.now().minus(1, ChronoUnit.DAYS).toString());

        mockMvc.perform(post("/api/v1/internal-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void listKeys_neverIncludesPlainKeyOrHash() throws Exception {
        Map<String, Object> body = Map.of("name", "k1");
        mockMvc.perform(post("/api/v1/internal-api-keys")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(body)));

        mockMvc.perform(get("/api/v1/internal-api-keys"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].plainKey").doesNotExist())
                .andExpect(jsonPath("$[0].keyHash").doesNotExist())
                .andExpect(jsonPath("$[0].keyPrefix").isString());
    }

    @Test
    void getKey_whenNotFound_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/internal-api-keys/{id}", 99999))
                .andExpect(status().isNotFound());
    }

    @Test
    void revokeKey_setsRevokedAt_andWritesAudit() throws Exception {
        Long id = createKey("to-revoke");
        auditLogRepository.deleteAll();

        mockMvc.perform(post("/api/v1/internal-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revokedAt").isString());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).hasSize(1);
        assertThat(logs.get(0).getAction()).isEqualTo(Action.APIKEY_REVOKE);
    }

    @Test
    void revokeKey_isIdempotent() throws Exception {
        Long id = createKey("two-revokes");

        String first = mockMvc.perform(post("/api/v1/internal-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String second = mockMvc.perform(post("/api/v1/internal-api-keys/{id}/revoke", id))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Object firstAt = objectMapper.readValue(first, Map.class).get("revokedAt");
        Object secondAt = objectMapper.readValue(second, Map.class).get("revokedAt");
        assertThat(firstAt).isEqualTo(secondAt);
    }

    private Long createKey(String name) throws Exception {
        Map<String, Object> body = Map.of("name", name);
        String response = mockMvc.perform(post("/api/v1/internal-api-keys")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andReturn().getResponse().getContentAsString();
        return ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();
    }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd admin-backend && ./gradlew test --tests "com.aag.admin.apikey.InternalApiKeyControllerTest" -i 2>&1 | tail -30`
Expected: 컴파일 에러 또는 FAIL (`InternalApiKeyController` 미존재)

- [ ] **Step 3: Commit (red 상태)**

```bash
git add admin-backend/src/test/java/com/aag/admin/apikey/InternalApiKeyControllerTest.java
git commit -m "test: InternalApiKeyController 실패 테스트 추가"
```

---

## Task 6: `InternalApiKeyController` 구현

**Files:**
- Create: `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyController.java`

- [ ] **Step 1: 컨트롤러 작성**

```java
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
```

- [ ] **Step 2: 테스트 통과 확인**

Run: `cd admin-backend && ./gradlew test --tests "com.aag.admin.apikey.InternalApiKeyControllerTest" 2>&1 | tail -20`
Expected: 7 tests PASS

- [ ] **Step 3: Commit**

```bash
git add admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyController.java
git commit -m "feat: InternalApiKeyController — CRUD + 1회 평문 노출 + 멱등 revoke"
```

---

## Task 7: `PolicyController.active` 제거 및 `GatewayPolicyController` 생성 (TDD)

**Files:**
- Create: `admin-backend/src/main/java/com/aag/admin/policy/GatewayPolicyController.java`
- Create: `admin-backend/src/test/java/com/aag/admin/policy/GatewayPolicyControllerTest.java`
- Modify: `admin-backend/src/main/java/com/aag/admin/policy/PolicyController.java` (remove `/active`)
- Modify: `admin-backend/src/test/java/com/aag/admin/policy/PolicyControllerTest.java` (remove `/active` 테스트 2건)

- [ ] **Step 1: `GatewayPolicyControllerTest` 실패 테스트 작성**

`admin-backend/src/test/java/com/aag/admin/policy/GatewayPolicyControllerTest.java`:

```java
package com.aag.admin.policy;

import com.aag.admin.apikey.InternalApiKeyRequest;
import com.aag.admin.apikey.InternalApiKeyService;
import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLog;
import com.aag.admin.audit.AuditLogRepository;
import com.aag.admin.apikey.InternalApiKeyRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class GatewayPolicyControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired PolicyRepository policyRepository;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired InternalApiKeyRepository apiKeyRepository;
    @Autowired InternalApiKeyService apiKeyService;

    private String validKey;

    @BeforeEach
    void seed() throws Exception {
        auditLogRepository.deleteAll();
        policyRepository.deleteAll();
        apiKeyRepository.deleteAll();

        InternalApiKeyRequest req = new InternalApiKeyRequest();
        req.setName("gw-test");
        validKey = apiKeyService.create(req).plainKey();
        auditLogRepository.deleteAll();

        Long id = createPolicy("active-one");
        mockMvc.perform(post("/api/v1/policies/{id}/activate", id));
        auditLogRepository.deleteAll();
    }

    @Test
    void gatewayActive_withValidKey_returnsPolicy_andWritesGatewayAudit() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("active-one"));

        // 이 테스트는 컨트롤러 책임만 검증한다. 필터(APIKEY_AUTH 로그)는 Task 8의
        // InternalApiKeyFilterTest 에서 별도로 검증한다.
        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.POLICY_REQUEST
                && l.getActionId() == ActorType.GATEWAY && l.isSuccess());
    }

    @Test
    void gatewayActive_whenNothingActive_returns404_andFailureAuditLog() throws Exception {
        policyRepository.deleteAll();
        auditLogRepository.deleteAll();

        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isNotFound());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.POLICY_REQUEST
                && l.getActionId() == ActorType.GATEWAY && !l.isSuccess());
    }

    private Long createPolicy(String name) throws Exception {
        Map<String, Object> body = Map.of(
                "name", name,
                "description", "",
                "l1Enabled", true, "l2Enabled", true, "l3Enabled", true,
                "l4Enabled", true, "l5Enabled", true, "l6Enabled", true
        );
        String response = mockMvc.perform(post("/api/v1/policies")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andReturn().getResponse().getContentAsString();
        return ((Number) objectMapper.readValue(response, Map.class).get("id")).longValue();
    }
}
```

- [ ] **Step 2: `PolicyControllerTest`에서 `/active` 테스트 2건 제거**

`admin-backend/src/test/java/com/aag/admin/policy/PolicyControllerTest.java`에서 다음 두 메서드를 삭제:
- `activeEndpoint_writesGatewayAuditLog_whenActiveExists()`
- `activeEndpoint_writesFailureAuditLog_whenNothingActive()`

- [ ] **Step 3: 테스트 실패 확인**

Run: `cd admin-backend && ./gradlew test --tests "com.aag.admin.policy.GatewayPolicyControllerTest" -i 2>&1 | tail -20`
Expected: FAIL (`GatewayPolicyController` 미존재 또는 경로 없음)

- [ ] **Step 4: `PolicyController`에서 `/active` 메서드 제거**

`admin-backend/src/main/java/com/aag/admin/policy/PolicyController.java` 에서 `@GetMapping("/active")` 메서드 전체(`public Map<String, Object> active()` 포함)를 삭제. 관련 import 중 사용하지 않게 되는 `Optional` import도 함께 제거.

- [ ] **Step 5: `GatewayPolicyController` 신규 작성**

`admin-backend/src/main/java/com/aag/admin/policy/GatewayPolicyController.java`:

```java
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
```

- [ ] **Step 6: Tag 업데이트 — `PolicyController`의 `@Tag` 설명 정리**

`PolicyController.java`의 `@Tag(name = "Policy", description = "L1~L6 가드레일 정책 관리 API")`는 그대로 유지(이미 맞음). 변경 없음.

- [ ] **Step 7: 테스트 실행 확인**

Run: `cd admin-backend && ./gradlew test --tests "com.aag.admin.policy.*" 2>&1 | tail -20`
Expected: `PolicyControllerTest` PASS (2건 감소) + `GatewayPolicyControllerTest` PASS.

이 시점엔 `InternalApiKeyFilter`가 없어 `/api/v1/gateway/**`는 permitAll이지만 `GatewayPolicyControllerTest`는 필터 책임을 검증하지 않으므로 통과한다. 필터 동작은 Task 8/9에서 별도 검증.

- [ ] **Step 8: Commit**

```bash
git add admin-backend/src/main/java/com/aag/admin/policy/ admin-backend/src/test/java/com/aag/admin/policy/
git commit -m "refactor: /policies/active를 /gateway/policies/active로 분리

PolicyController에서 /active 엔드포인트를 제거하고 GatewayPolicyController
(새 파일)의 /api/v1/gateway/policies/active로 이동한다. Gateway 전용
URL prefix를 명시적으로 드러내어 추후 필터 보호 대상을 URL 규칙만으로
식별할 수 있게 한다."
```

---

## Task 8: `InternalApiKeyFilter` 테스트 먼저 작성 (TDD)

**Files:**
- Create: `admin-backend/src/test/java/com/aag/admin/apikey/InternalApiKeyFilterTest.java`

- [ ] **Step 1: 실패 테스트 작성**

```java
package com.aag.admin.apikey;

import com.aag.admin.audit.Action;
import com.aag.admin.audit.ActorType;
import com.aag.admin.audit.AuditLog;
import com.aag.admin.audit.AuditLogRepository;
import com.aag.admin.policy.Policy;
import com.aag.admin.policy.PolicyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class InternalApiKeyFilterTest {

    @Autowired MockMvc mockMvc;
    @Autowired InternalApiKeyRepository apiKeyRepository;
    @Autowired InternalApiKeyService apiKeyService;
    @Autowired AuditLogRepository auditLogRepository;
    @Autowired PolicyRepository policyRepository;

    private String validKey;

    @BeforeEach
    void seed() {
        auditLogRepository.deleteAll();
        apiKeyRepository.deleteAll();
        policyRepository.deleteAll();

        Policy p = new Policy();
        p.setName("active");
        p.setUse(true);
        policyRepository.save(p);

        InternalApiKeyRequest req = new InternalApiKeyRequest();
        req.setName("k");
        validKey = apiKeyService.create(req).plainKey();
        auditLogRepository.deleteAll();
    }

    @Test
    void gatewayEndpoint_withValidKey_returns200_updatesLastUsedAt_writesSuccessAudit() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isOk());

        List<InternalApiKey> keys = apiKeyRepository.findAll();
        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).getLastUsedAt()).isNotNull();

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.APIKEY_AUTH
                && l.getActionId() == ActorType.GATEWAY && l.isSuccess());
    }

    @Test
    void gatewayEndpoint_withoutHeader_returns401_writesFailAudit() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/policies/active"))
                .andExpect(status().isUnauthorized());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.APIKEY_AUTH
                && l.getActionId() == ActorType.GATEWAY && !l.isSuccess()
                && l.getDetail().contains("missing"));
    }

    @Test
    void gatewayEndpoint_withUnknownKey_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", "iak_deadbeef"))
                .andExpect(status().isUnauthorized());

        List<AuditLog> logs = auditLogRepository.findAll();
        assertThat(logs).anyMatch(l -> l.getAction() == Action.APIKEY_AUTH && !l.isSuccess());
    }

    @Test
    void gatewayEndpoint_withRevokedKey_returns401() throws Exception {
        InternalApiKey key = apiKeyRepository.findAll().get(0);
        apiKeyService.revoke(key);
        auditLogRepository.deleteAll();

        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void gatewayEndpoint_withExpiredKey_returns401() throws Exception {
        InternalApiKey key = apiKeyRepository.findAll().get(0);
        key.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
        apiKeyRepository.save(key);
        auditLogRepository.deleteAll();

        mockMvc.perform(get("/api/v1/gateway/policies/active").header("X-API-Key", validKey))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void nonGatewayEndpoint_isNotAffectedByFilter() throws Exception {
        mockMvc.perform(get("/api/v1/policies"))
                .andExpect(status().isOk());
    }
}
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd admin-backend && ./gradlew test --tests "com.aag.admin.apikey.InternalApiKeyFilterTest" 2>&1 | tail -30`
Expected: FAIL (401 기대했는데 200, 필터 미등록)

- [ ] **Step 3: Commit (red 상태)**

```bash
git add admin-backend/src/test/java/com/aag/admin/apikey/InternalApiKeyFilterTest.java
git commit -m "test: InternalApiKeyFilter 실패 테스트 추가"
```

---

## Task 9: `InternalApiKeyFilter` + SecurityConfig 구현

**Files:**
- Create: `admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyFilter.java`
- Modify: `admin-backend/src/main/java/com/aag/admin/config/SecurityConfig.java`

- [ ] **Step 1: `InternalApiKeyFilter` 작성**

```java
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
```

- [ ] **Step 2: `SecurityConfig` 수정 — 필터 체인에 등록**

`admin-backend/src/main/java/com/aag/admin/config/SecurityConfig.java` 전체 교체:

```java
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
```

- [ ] **Step 3: `InternalApiKeyFilterTest` 통과 확인**

Run: `cd admin-backend && ./gradlew test --tests "com.aag.admin.apikey.InternalApiKeyFilterTest" 2>&1 | tail -20`
Expected: 6 tests PASS

- [ ] **Step 4: 전체 백엔드 테스트 통과 확인**

Run: `cd admin-backend && ./gradlew test 2>&1 | tail -20`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add admin-backend/src/main/java/com/aag/admin/apikey/InternalApiKeyFilter.java admin-backend/src/main/java/com/aag/admin/config/SecurityConfig.java
git commit -m "feat: InternalApiKeyFilter로 /api/v1/gateway/** 보호

OncePerRequestFilter 상속. X-API-Key 헤더를 SHA-256 해시하여
internal_api_keys 테이블과 매칭, 활성 키면 통과 + lastUsedAt 갱신 +
APIKEY_AUTH(success=true) 감사로그. 실패 시 401 JSON + 실패 로그.
AntPathMatcher로 /api/v1/gateway/** 경로에만 적용, 관리자 UI용
엔드포인트는 지나친다."
```

---

## Task 10: 프론트엔드 `InternalApiKeysPage` 테스트 먼저 작성 (TDD)

**Files:**
- Create: `admin-frontend/src/__tests__/InternalApiKeysPage.test.tsx`

- [ ] **Step 1: 실패 테스트 작성**

```tsx
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { InternalApiKeysPage } from '@/pages/InternalApiKeysPage';

const mockKeys = [
  {
    id: 1,
    name: 'gw-prod-01',
    description: '운영 Gateway',
    keyPrefix: 'iak_AbCdEfGh',
    expiresAt: null,
    revokedAt: null,
    lastUsedAt: '2026-04-14T10:00:00Z',
    createdAt: '2026-04-10T00:00:00Z',
    updatedAt: '2026-04-14T10:00:00Z',
  },
  {
    id: 2,
    name: 'gw-old',
    description: null,
    keyPrefix: 'iak_ZzYyXxWw',
    expiresAt: null,
    revokedAt: '2026-04-12T00:00:00Z',
    lastUsedAt: null,
    createdAt: '2026-04-01T00:00:00Z',
    updatedAt: '2026-04-12T00:00:00Z',
  },
];

describe('InternalApiKeysPage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const renderPage = () =>
    render(
      <MemoryRouter>
        <InternalApiKeysPage />
      </MemoryRouter>,
    );

  it('마운트 시 목록을 가져와 렌더링한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockKeys), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('gw-prod-01')).toBeInTheDocument();
    expect(screen.getByText('gw-old')).toBeInTheDocument();
  });

  it('활성 키와 폐기된 키를 각각의 칩으로 구분해 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(mockKeys), { status: 200 }),
    );
    renderPage();
    expect(await screen.findByText('활성')).toBeInTheDocument();
    expect(screen.getByText('폐기됨')).toBeInTheDocument();
  });

  it('새 키 발급 폼 제출 시 POST 호출 + plainKey 모달을 표시한다', async () => {
    const created = {
      id: 3,
      name: '신규',
      description: '',
      keyPrefix: 'iak_NnNnNnNn',
      expiresAt: null,
      revokedAt: null,
      lastUsedAt: null,
      createdAt: '2026-04-17T00:00:00Z',
      updatedAt: '2026-04-17T00:00:00Z',
      plainKey: 'iak_NnNnNnNnAaBbCcDdEeFfGgHhIiJjKk',
    };
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(created), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([...mockKeys, created]), { status: 200 }));

    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /새 키/ }));
    await userEvent.type(screen.getByLabelText('이름'), '신규');
    await userEvent.click(screen.getByRole('button', { name: '발급' }));

    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          typeof url === 'string' &&
          url === '/api/v1/internal-api-keys' &&
          (init as RequestInit | undefined)?.method === 'POST',
      );
      expect(postCall).toBeTruthy();
    });

    expect(await screen.findByText(created.plainKey)).toBeInTheDocument();
    expect(screen.getByText(/다시 볼 수 없습니다/)).toBeInTheDocument();
  });

  it('평문 노출 모달의 복사 버튼은 navigator.clipboard.writeText를 호출한다', async () => {
    const created = {
      id: 4,
      name: 'x',
      description: null,
      keyPrefix: 'iak_Cccccccc',
      expiresAt: null,
      revokedAt: null,
      lastUsedAt: null,
      createdAt: '2026-04-17T00:00:00Z',
      updatedAt: '2026-04-17T00:00:00Z',
      plainKey: 'iak_CcccccccCOPY',
    };
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(created), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([created]), { status: 200 }));

    renderPage();
    await userEvent.click(await screen.findByRole('button', { name: /새 키/ }));
    await userEvent.type(screen.getByLabelText('이름'), 'x');
    await userEvent.click(screen.getByRole('button', { name: '발급' }));

    await screen.findByText('iak_CcccccccCOPY');
    await userEvent.click(screen.getByRole('button', { name: '복사' }));
    expect(writeText).toHaveBeenCalledWith('iak_CcccccccCOPY');
  });

  it('폐기 버튼 클릭 시 confirm을 통과하면 revoke POST를 호출한다', async () => {
    const confirmSpy = vi.spyOn(globalThis, 'confirm').mockReturnValue(true);
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({}), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(mockKeys), { status: 200 }));

    renderPage();
    await screen.findByText('gw-prod-01');
    await userEvent.click(screen.getByRole('button', { name: '폐기' }));

    expect(confirmSpy).toHaveBeenCalled();
    await waitFor(() => {
      const revokeCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          typeof url === 'string' &&
          url === '/api/v1/internal-api-keys/1/revoke' &&
          (init as RequestInit | undefined)?.method === 'POST',
      );
      expect(revokeCall).toBeTruthy();
    });
  });

  it('로딩 실패 시 오류 메시지를 표시한다', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('err', { status: 500 }));
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent(/불러오지 못했습니다/);
  });
});
```

- [ ] **Step 2: 테스트 실패 확인**

Run: `cd admin-frontend && npx vitest run src/__tests__/InternalApiKeysPage.test.tsx 2>&1 | tail -20`
Expected: FAIL (`InternalApiKeysPage` import 실패)

- [ ] **Step 3: Commit (red 상태)**

```bash
git add admin-frontend/src/__tests__/InternalApiKeysPage.test.tsx
git commit -m "test: InternalApiKeysPage 실패 테스트 추가"
```

---

## Task 11: 프론트엔드 `InternalApiKeysPage` 구현

**Files:**
- Create: `admin-frontend/src/pages/InternalApiKeysPage.tsx`

- [ ] **Step 1: 페이지 작성**

```tsx
import { FormEvent, useCallback, useEffect, useState } from 'react';

type ApiKey = {
  id: number;
  name: string;
  description: string | null;
  keyPrefix: string;
  expiresAt: string | null;
  revokedAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

type IssuedKey = ApiKey & { plainKey: string };

const API = '/api/v1/internal-api-keys';

function formatDateTime(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function statusChip(key: ApiKey) {
  if (key.revokedAt) {
    return <span className="chip chip--fail">폐기됨</span>;
  }
  if (key.expiresAt && new Date(key.expiresAt) <= new Date()) {
    return <span className="chip">만료</span>;
  }
  return <span className="chip chip--success">활성</span>;
}

export function InternalApiKeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [showForm, setShowForm] = useState(false);
  const [creating, setCreating] = useState(false);
  const [draftName, setDraftName] = useState('');
  const [draftDesc, setDraftDesc] = useState('');
  const [draftExpires, setDraftExpires] = useState('');

  const [issued, setIssued] = useState<IssuedKey | null>(null);

  const loadKeys = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch(API);
      if (!res.ok) {
        setError('API 키를 불러오지 못했습니다.');
        return;
      }
      setKeys((await res.json()) as ApiKey[]);
    } catch {
      setError('API 키를 불러오지 못했습니다.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadKeys();
  }, [loadKeys]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (creating || !draftName.trim()) return;
    setCreating(true);
    try {
      const body: Record<string, unknown> = { name: draftName.trim() };
      if (draftDesc.trim()) body.description = draftDesc.trim();
      if (draftExpires) body.expiresAt = new Date(draftExpires).toISOString();

      const res = await fetch(API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        setError('API 키 발급에 실패했습니다.');
        return;
      }
      const created = (await res.json()) as IssuedKey;
      setIssued(created);
      setShowForm(false);
      setDraftName('');
      setDraftDesc('');
      setDraftExpires('');
      await loadKeys();
    } catch {
      setError('API 키 발급에 실패했습니다.');
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(key: ApiKey) {
    if (!confirm(`이 키를 폐기하면 해당 키로 접속하는 Gateway는 즉시 401을 받습니다.\n진행하시겠습니까?\n\n이름: ${key.name}\nPrefix: ${key.keyPrefix}`)) {
      return;
    }
    try {
      const res = await fetch(`${API}/${key.id}/revoke`, { method: 'POST' });
      if (!res.ok) {
        setError('API 키 폐기에 실패했습니다.');
        return;
      }
      await loadKeys();
    } catch {
      setError('API 키 폐기에 실패했습니다.');
    }
  }

  async function handleCopyPlainKey() {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued.plainKey);
    } catch {
      /* 복사 실패 시 조용히 무시 — 사용자는 수동 복사 가능 */
    }
  }

  return (
    <div>
      <h2 className="page-title">Internal API 키</h2>
      <p className="page-subtitle">
        Admin↔Gateway 서비스 간 인증용 키입니다. 발급된 평문 키는 **이 발급 직후에만** 확인할 수 있습니다.
      </p>

      {error && <div className="alert" role="alert">{error}</div>}

      <div className="card">
        <div className="card__header">
          <h3 className="card__title">키 목록</h3>
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => setShowForm((s) => !s)}
          >
            {showForm ? '취소' : '+ 새 키'}
          </button>
        </div>

        {showForm && (
          <form onSubmit={handleCreate} className="inline-form" aria-label="새 API 키">
            <div className="filter-field">
              <label htmlFor="key-name">이름</label>
              <input
                id="key-name"
                type="text"
                value={draftName}
                onChange={(e) => setDraftName(e.target.value)}
                required
                disabled={creating}
              />
            </div>
            <div className="filter-field" style={{ flex: 1, minWidth: 200 }}>
              <label htmlFor="key-desc">설명</label>
              <input
                id="key-desc"
                type="text"
                value={draftDesc}
                onChange={(e) => setDraftDesc(e.target.value)}
                disabled={creating}
              />
            </div>
            <div className="filter-field">
              <label htmlFor="key-expires">만료일 (선택)</label>
              <input
                id="key-expires"
                type="date"
                value={draftExpires}
                onChange={(e) => setDraftExpires(e.target.value)}
                disabled={creating}
              />
            </div>
            <button type="submit" className="btn btn--primary" disabled={creating}>
              {creating ? '발급 중...' : '발급'}
            </button>
          </form>
        )}

        {loading ? (
          <p className="empty-message">불러오는 중...</p>
        ) : keys.length === 0 ? (
          <p className="empty-message">발급된 키가 없습니다.</p>
        ) : (
          <table aria-label="API 키 목록">
            <thead>
              <tr>
                <th>이름</th>
                <th>설명</th>
                <th>Prefix</th>
                <th>만료일</th>
                <th>마지막 사용</th>
                <th style={{ textAlign: 'center' }}>상태</th>
                <th style={{ textAlign: 'right' }}>액션</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.id}>
                  <td>{key.name}</td>
                  <td style={{ color: 'var(--raon-text-sub)' }}>{key.description || '—'}</td>
                  <td style={{ fontFamily: 'monospace' }}>{key.keyPrefix}</td>
                  <td>{formatDate(key.expiresAt)}</td>
                  <td>{formatDateTime(key.lastUsedAt)}</td>
                  <td style={{ textAlign: 'center' }}>{statusChip(key)}</td>
                  <td style={{ textAlign: 'right' }}>
                    {!key.revokedAt && (
                      <button
                        type="button"
                        className="btn btn--sm btn--danger"
                        onClick={() => handleRevoke(key)}
                      >
                        폐기
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {issued && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="새 API 키 발급 결과"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
        >
          <div className="card" style={{ maxWidth: 560, margin: 0 }}>
            <div className="card__header">
              <h3 className="card__title">API 키 발급 완료</h3>
            </div>
            <p className="page-subtitle" style={{ color: 'var(--raon-danger, #b00020)' }}>
              ⚠️ 이 창을 닫으면 평문 키를 다시 볼 수 없습니다. 지금 복사해서 Gateway 환경변수에 저장하세요.
            </p>
            <pre
              style={{
                background: '#f5f5f5',
                padding: 12,
                borderRadius: 6,
                overflowX: 'auto',
                fontFamily: 'monospace',
              }}
            >
              {issued.plainKey}
            </pre>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 12 }}>
              <button type="button" className="btn btn--sm" onClick={handleCopyPlainKey}>
                복사
              </button>
              <button
                type="button"
                className="btn btn--sm btn--primary"
                onClick={() => setIssued(null)}
              >
                확인
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: 테스트 통과 확인**

Run: `cd admin-frontend && npx vitest run src/__tests__/InternalApiKeysPage.test.tsx 2>&1 | tail -20`
Expected: 6 tests PASS

- [ ] **Step 3: Commit**

```bash
git add admin-frontend/src/pages/InternalApiKeysPage.tsx
git commit -m "feat: InternalApiKeysPage — 키 발급/목록/폐기 UI + 평문 1회 노출 모달"
```

---

## Task 12: 라우트 및 사이드바 메뉴 추가

**Files:**
- Modify: `admin-frontend/src/App.tsx`

- [ ] **Step 1: App.tsx 수정**

기존:
```tsx
import { LayerSettingsPage } from '@/pages/LayerSettingsPage';
import { AuditLogPage } from '@/pages/AuditLogPage';
```

다음으로 변경:
```tsx
import { LayerSettingsPage } from '@/pages/LayerSettingsPage';
import { AuditLogPage } from '@/pages/AuditLogPage';
import { InternalApiKeysPage } from '@/pages/InternalApiKeysPage';
```

기존 사이드바:
```tsx
<NavLink
  to="/admin/audit-logs"
  className={({ isActive }) => `app-sidebar__item${isActive ? ' active' : ''}`}
>
  감사 로그
</NavLink>
```

바로 뒤에 추가:
```tsx
<NavLink
  to="/admin/audit-logs"
  className={({ isActive }) => `app-sidebar__item${isActive ? ' active' : ''}`}
>
  감사 로그
</NavLink>
<NavLink
  to="/admin/internal-api-keys"
  className={({ isActive }) => `app-sidebar__item${isActive ? ' active' : ''}`}
>
  Internal API 키
</NavLink>
```

기존 라우트:
```tsx
<Route path="/admin/audit-logs" element={<AuditLogPage />} />
```

바로 뒤에 추가:
```tsx
<Route path="/admin/audit-logs" element={<AuditLogPage />} />
<Route path="/admin/internal-api-keys" element={<InternalApiKeysPage />} />
```

- [ ] **Step 2: 프론트엔드 빌드 확인**

Run: `cd admin-frontend && npm run build 2>&1 | tail -10`
Expected: build 성공

- [ ] **Step 3: 전체 프론트엔드 테스트 통과 확인**

Run: `cd admin-frontend && npx vitest run 2>&1 | tail -20`
Expected: 모든 테스트 PASS

- [ ] **Step 4: Commit**

```bash
git add admin-frontend/src/App.tsx
git commit -m "feat: 사이드바에 Internal API 키 메뉴 및 /admin/internal-api-keys 라우트 추가"
```

---

## Task 13: Docker 재빌드 및 수동 검증

**Files:** (없음 — 인프라 검증)

- [ ] **Step 1: DB 볼륨 리셋 (스키마 변경으로 인한 안전 조치)**

```bash
docker compose down
docker volume rm agentic-ai-guardrail_postgres-data
```

- [ ] **Step 2: 이미지 재빌드 및 기동**

```bash
docker compose up -d --build
```

Expected: 3개 컨테이너(postgres, admin-backend, admin-frontend) 모두 기동 + postgres healthy

- [ ] **Step 3: 수동 검증 — 키 발급**

```bash
curl -s -X POST http://localhost:8080/api/v1/internal-api-keys \
  -H 'Content-Type: application/json' \
  -d '{"name":"test","description":"수동검증"}'
```

Expected: 201 응답, 본문에 `plainKey` 포함 (`iak_` 로 시작, 36자)

- [ ] **Step 4: 수동 검증 — Gateway 엔드포인트 401 (헤더 없음)**

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/v1/gateway/policies/active
```

Expected: `401`

- [ ] **Step 5: 수동 검증 — Gateway 엔드포인트 통과 (유효 키)**

Step 3에서 받은 `plainKey`를 `$KEY` 변수에 설정한 뒤:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "X-API-Key: $KEY" \
  http://localhost:8080/api/v1/gateway/policies/active
```

Expected: `404` (활성 정책 없을 때) 또는 `200` (있을 때). 핵심은 401이 아니어야 함.

- [ ] **Step 6: 수동 검증 — 프론트엔드 UI**

브라우저에서 `http://localhost:8080/admin/internal-api-keys` 접속:
- 목록에 Step 3에서 발급한 "test" 키 표시
- "+ 새 키" → 이름 입력 → 발급 → 모달에 `plainKey` 노출
- 모달 복사 버튼 → 확인 버튼 닫기
- "폐기" 버튼 → confirm → 키 상태 "폐기됨" 전환

- [ ] **Step 7: (문제 없으면) Docker 파일은 커밋 안 함**

`docker-compose.yml` / `Dockerfile` 등은 이전 커밋 관행대로 커밋하지 않음. `git status`에 남아있어도 OK.

---

## Task 14: 전체 통합 푸시

- [ ] **Step 1: 전체 브랜치 로그 확인**

```bash
git log --oneline origin/admin..HEAD
```

Expected: Task 1~12 의 커밋이 순서대로 표시

- [ ] **Step 2: Push**

```bash
git push origin admin
```

Expected: 모든 커밋이 `origin/admin` 으로 업로드

- [ ] **Step 3: PR 상태 확인 (기존 PR #12가 열려 있으면 자동 갱신됨)**

기존 PR이 있으면 push만으로 자동 업데이트되므로 추가 작업 불필요. 없으면 git credential 기반 GitHub API로 생성:

```bash
TOKEN=$(git credential fill <<EOF 2>/dev/null | grep '^password=' | cut -d= -f2
protocol=https
host=github.com
EOF
)

curl -s -X POST https://api.github.com/repos/djpark0402/agentic-ai-guardrail/pulls \
  -H "Authorization: token ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "feat: Internal API Key 기능 추가 (Admin↔Gateway 내부 인증)",
    "head": "admin",
    "base": "develop",
    "body": "Internal API Key 발급/폐기/검증 기능 + /api/v1/gateway/** 보호 필터. 스펙: docs/superpowers/specs/2026-04-17-internal-api-key-design.md"
  }'
```

Expected: PR URL 반환
