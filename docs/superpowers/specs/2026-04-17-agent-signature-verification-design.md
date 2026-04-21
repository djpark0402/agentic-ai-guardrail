# Agent 서명 검증 + 정책 통합 응답 설계

## 1. 배경 및 목적

외부 고객사(Agent)가 Guardrail Gateway를 호출할 때, 메시지 위·변조와 신원 사칭을 막기 위한 HMAC 기반 인증을 도입한다. 인증의 비밀 자료(API Key, Secret Key)는 Admin 서버가 발급·관리하며, 서명 검증도 Admin이 단독으로 수행한다.

검증 단계에서 Gateway는 동일 응답으로 현재 활성 정책까지 함께 받아가도록 하여, 요청당 Admin 호출을 1번으로 유지한다.

전체 플로우:
```
Agent  →  Gateway  →  Admin
  │         │           │
  │         │       (1) timestamp skew
  │         │       (2) findByApiKeyHash
  │         │       (3) decrypt secret (KeyStore AES)
  │         │       (4) HMAC-SHA256 재계산 + 비교
  │         │       (5) findByIsUseTrue (활성 정책)
  │         │       (6) AGENT_AUTH 감사 로그
  │         │  ←  { valid, clientName, agentKeyId, policy }
  │     (7) 정책에 따라 레이어 실행
  │  ←  결과
```

## 2. 범위

본 문서는 **Admin 백엔드(Spring Boot)와 Admin 프론트엔드(React)만** 다룬다. Gateway(FastAPI)와 Agent SDK 구현은 별도 팀이 담당하지만, 서명 스킴/요청 형식/응답 형식은 Admin이 게시하는 계약이므로 본 문서가 정의한다.

기존 Internal API Key 시스템(Admin↔Gateway 서비스 간 인증)은 그대로 사용한다. 신규 `/api/v1/gateway/verify` 엔드포인트도 InternalApiKey 필터로 보호된다.

## 3. 서명 스킴

### 3.1 캐논파이즈 규칙

| 항목 | 규칙 |
|---|---|
| `body` | HTTP request body의 raw bytes (파싱·재직렬화 금지) |
| `bodyHash` | `SHA-256(body)` → **lowercase hex 64자** |
| `timestamp` | Unix epoch 초, 문자열 |
| `nonce` | URL-safe ASCII 임의 문자열 (Agent가 생성) |
| `canonical` | `f"{timestamp}.{nonce}.{bodyHash}"` UTF-8 encode |
| `signature` | `HMAC-SHA256(secret, canonical)` → **lowercase hex 64자** |
| 빈 body | `SHA-256("")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

`bodyHash`를 사이에 끼우는 이유는 Admin이 본문 내용을 보지 않고도 검증 가능하게 하고, Admin↔Gateway 네트워크 비용을 일정하게 유지하기 위함이다 (AWS SigV4와 동일 패턴).

### 3.2 Agent → Gateway 헤더

```
X-API-Key:   ak_...
X-Timestamp: 1745000000
X-Nonce:     a1b2c3
X-Signature: <sha256hex>
```

### 3.3 Gateway → Admin 페이로드

Gateway는 자체 `bodyHash`를 계산하여 Admin에게 전달한다. body 자체는 보내지 않는다.

```json
{
  "apiKey":    "ak_...",
  "timestamp": "1745000000",
  "nonce":     "a1b2c3",
  "bodyHash":  "<sha256hex>",
  "signature": "<sha256hex>"
}
```

## 4. 데이터 모델

### 4.1 `agent_api_keys` 테이블

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | BIGINT PK | IDENTITY | |
| `client_name` | VARCHAR(100) | NOT NULL | 고객사명 (응답의 `clientName`) |
| `description` | VARCHAR(500) | NULL | 메모 |
| `api_key_hash` | VARCHAR(64) | NOT NULL, UNIQUE | `SHA-256(apiKey 평문)` lowercase hex |
| `key_prefix` | VARCHAR(12) | NOT NULL | 평문 앞 12자 (`ak_` + 8 random chars). UI/감사로그 식별용 |
| `secret_encrypted` | BYTEA | NOT NULL | AES-GCM 암호문. `[12B IV][ciphertext][16B tag]` 연속 저장 |
| `expires_at` | TIMESTAMP | NULL | null = 무기한 |
| `revoked_at` | TIMESTAMP | NULL | null = 활성 |
| `last_used_at` | TIMESTAMP | NULL | 마지막 성공 검증 시각 |
| `created_at` | TIMESTAMP | NOT NULL, not updatable | |
| `updated_at` | TIMESTAMP | NOT NULL | |

### 4.2 키 포맷

- `apiKey` 평문: `ak_` + Base64urlNoPad(24 bytes) = **35자**, 192비트 엔트로피
- `secret` 평문: Base64urlNoPad(32 bytes) = **43자**, 256비트 엔트로피
- `apiKey` 는 공개 식별자 성격이지만, DB 덤프 방어 + InternalApiKey 패턴 일관성을 위해 **해시 저장**. 평문은 발급 응답에만 1회 노출.
- `secret` 은 검증 시 복원 필요 → AES-GCM 암호화 저장. 평문은 발급 응답에만 1회 노출.
- 두 평문 모두 발급 시점 이후 시스템 어디에도 저장되지 않음.

### 4.3 활성 판단

```sql
revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now())
```

### 4.4 로테이션

별도 rotate 엔드포인트 없음. 운영 절차: "새 키 발급 → 구키 revoke" 2-step. 다건 활성 가능.

## 5. AES 암호화 (KeyStore)

### 5.1 알고리즘

- **AES-GCM / 256-bit**
- IV: 12 bytes 랜덤 (매 암호화마다 `SecureRandom`)
- 인증 태그: 128-bit
- `secret_encrypted` 컬럼 저장 포맷: `[12B IV][ciphertext][16B tag]` 연속 단일 byte[]. 복호화 시 앞 12바이트가 IV.

### 5.2 KeyStore

**파일**: PKCS#12 (`.p12`) — Java 17 기본 지원, OpenSSL/keytool 호환.

**생성 (운영자 1회)**:
```bash
keytool -genseckey \
  -alias aag-secret-aes \
  -keyalg AES -keysize 256 \
  -storetype PKCS12 \
  -keystore aag-keystore.p12 \
  -storepass "${KEYSTORE_PASSWORD}"
```

**파일 배포**:
- 운영/스테이징/로컬 환경별 별도 KeyStore.
- KeyStore 파일은 **git ignore**. 환경별 시크릿 채널(예: 직접 전달, KMS export 등)로 배포.
- 로컬 개발은 docker-compose가 `./admin-backend/config/aag-keystore.p12` 를 컨테이너에 read-only 볼륨 마운트.
- 테스트용 더미 KeyStore (`src/test/resources/test-keystore.p12`) 1개는 repo에 커밋. 더미 비밀번호도 application-test.yml 에 넣음.

### 5.3 설정

`application.yml`:
```yaml
aag:
  crypto:
    keystore-path: ${AAG_KEYSTORE_PATH:config/aag-keystore.p12}
    keystore-password: ${AAG_KEYSTORE_PASSWORD:}
    key-alias: ${AAG_KEYSTORE_KEY_ALIAS:aag-secret-aes}
```
- `AAG_KEYSTORE_PASSWORD` 환경변수 필수. 미설정 시 앱 기동 실패(fail-fast). yml 기본값은 의도적으로 비움.

`docker-compose.yml`:
```yaml
admin-backend:
  volumes:
    - ./admin-backend/config/aag-keystore.p12:/app/config/aag-keystore.p12:ro
  environment:
    AAG_KEYSTORE_PATH: /app/config/aag-keystore.p12
    AAG_KEYSTORE_PASSWORD: ${AAG_KEYSTORE_PASSWORD:?required}
    AAG_KEYSTORE_KEY_ALIAS: aag-secret-aes
```

### 5.4 `SecretCipher` 컴포넌트

- 패키지: `com.aag.admin.crypto.SecretCipher`
- 생성자에서 KeyStore 1회 로드 → `SecretKey` 인스턴스를 final 필드로 보관.
- API:
  ```java
  byte[] encrypt(String plaintext);   // IV 포함 결합 byte[] 리턴
  String decrypt(byte[] combined);    // IV 추출해 복호화, UTF-8 String
  ```
- `Cipher` 인스턴스는 매 호출마다 `Cipher.getInstance("AES/GCM/NoPadding")` 로 생성 (Cipher는 thread-unsafe).
- `SecretKey` 는 불변이므로 공유 안전.

## 6. API

### 6.1 Admin UI용 — `/api/v1/agent-api-keys`

| 메서드 | 경로 | 요청 | 응답 |
|---|---|---|---|
| POST | `/` | `{clientName, description?, expiresAt?}` | `201` + 단건 메타 + **`apiKey`** + **`secret`** (이 응답에만) |
| GET | `/` | — | `[{id, clientName, description, keyPrefix, expiresAt, revokedAt, lastUsedAt, createdAt, updatedAt}]` |
| GET | `/{id}` | — | 목록 단건 스키마 |
| POST | `/{id}/revoke` | — | 단건 + `revokedAt` 채워짐 (멱등) |

**Validation:**
- `clientName`: NotBlank, max 100
- `description`: max 500
- `expiresAt`: 미래 시각만 (과거면 400, `BadRequestException("expiresAt must be in the future")`)

**보안:**
- 응답 어디에도 `apiKeyHash`, `secret`, `secret_encrypted` 노출 금지 (단, 발급 응답의 `apiKey`, `secret` 평문은 예외).
- `keyPrefix` 만으로 UI/감사로그에서 키 식별.

**감사 로그:**
- create → `ADMIN/AGENT_KEY_CREATE/success=true, detail="id=X, clientName=Y, keyPrefix=ak_AbCd..."`
- revoke (활성 → 폐기) → `ADMIN/AGENT_KEY_REVOKE/success=true, detail="id=X, clientName=Y, keyPrefix=..."`
- revoke 멱등 (이미 폐기) → 감사 로그 미기록 (InternalApiKey 패턴과 동일)

### 6.2 Gateway용 — `POST /api/v1/gateway/verify`

기존 `InternalApiKeyFilter` 가 이 경로를 자동 보호한다. 즉 Gateway는 **`X-API-Key: iak_...`** (InternalApiKey) 헤더가 필수.

**Request:**
```json
{
  "apiKey":    "ak_...",
  "timestamp": "1745000000",
  "nonce":     "a1b2c3",
  "bodyHash":  "<sha256hex>",
  "signature": "<sha256hex>"
}
```
모든 필드 NotBlank. 누락 시 400.

**검증 순서:**

1. **Timestamp skew**
   - `|currentEpochSecond - parseLong(timestamp)| > 300` → `valid:false, reason:timestamp_skew`
   - timestamp 파싱 실패도 동일 reason
2. **Lookup**
   - `hash = SHA-256(apiKey)`
   - `repository.findByApiKeyHash(hash)`
   - 없음 → `unknown_key`
   - `revoked_at != null` → `revoked`
   - `expires_at != null && !expires_at.isAfter(now)` → `expired`
3. **Decrypt secret**
   - `secretCipher.decrypt(row.secret_encrypted)`
4. **HMAC 재계산**
   - `canonical = timestamp + "." + nonce + "." + bodyHash`
   - `expected = HmacSha256(secret, canonical).toLowerCaseHex()`
   - `MessageDigest.isEqual(expected.getBytes(), signature.getBytes())` (constant-time)
   - 불일치 → `invalid_signature`
5. **Active policy**
   - `policyRepository.findByIsUseTrue()` empty → `no_active_policy`
6. **Side effects**
   - `row.lastUsedAt = now()`; save
   - `auditLogService.record(GATEWAY, AGENT_AUTH, true, "clientName=Y, agentKeyId=42")`

**성공 응답 (200):**
```json
{
  "valid": true,
  "clientName": "고객사A",
  "agentKeyId": 42,
  "policy": {
    "id": 1,
    "name": "default-strict",
    "l1Enabled": true,
    "l2Enabled": false,
    "l3Enabled": true,
    "l4Enabled": true,
    "l5Enabled": false,
    "l6Enabled": true
  }
}
```

**실패 응답 (200, `valid:false`):**
```json
{ "valid": false, "reason": "invalid_signature" }
```

**실패 reason 값 (전체 enum):**
- `timestamp_skew`
- `unknown_key`
- `revoked`
- `expired`
- `invalid_signature`
- `no_active_policy`

**Request 자체 불량 (400):**
- 필드 누락, 바인딩 실패는 200+reason 이 아니라 기존 `ApiExceptionHandler` 의 400 envelope.

**감사 로그:**
- 성공: `GATEWAY/AGENT_AUTH/success=true, detail="clientName=Y, agentKeyId=42"`
- 실패 (모든 reason): `GATEWAY/AGENT_AUTH/success=false, detail="reason=<R>, apiKeyPrefix=ak_AbCd..."`
  - 단 `unknown_key` 는 prefix를 알 수 없으므로 `detail="reason=unknown_key, apiKeyPrefix=<입력값 앞 12자>"` (정상 포맷이라면 `ak_xxxxxxxx`)

### 6.3 기존 `GET /api/v1/gateway/policies/active` 제거

`/verify` 엔드포인트가 활성 정책을 함께 내리므로 별도 정책 조회 엔드포인트는 필요 없다. 컨트롤러 메서드, 테스트, Swagger 문서에서 모두 제거. `GatewayPolicyController` 자체는 `/verify` 엔드포인트를 새로 호스팅하는 컨트롤러로 재용도(또는 새 `GatewayVerifyController` 분리). 추후 구현 계획에서 확정.

## 7. 감사 로그 Action enum 추가

```java
AGENT_KEY_CREATE("Agent API 키 생성"),
AGENT_KEY_REVOKE("Agent API 키 폐기"),
AGENT_AUTH("Agent 서명 검증"),
```

ActorType 매핑은 §6.1 / §6.2 의 표 참고.

`AGENT_AUTH` 는 모든 Agent 요청마다 1건씩 생성되어 볼륨이 클 수 있다. MVP 단계에서는 전건 동기 기록한다. 운영 단계에서 (a) 실패만 기록 (b) 별도 테이블 (c) 비동기 처리 등을 검토하지만 본 스펙 범위가 아니다.

## 8. 프론트엔드

### 8.1 라우트 / 메뉴

- 신규 페이지: `AgentApiKeysPage` (`src/pages/AgentApiKeysPage.tsx`)
- 라우트: `/admin/agent-api-keys`
- 사이드바 순서: Layer 설정 / 감사 로그 / Internal API 키 / **Agent API 키** (신규)

### 8.2 목록 테이블

| 컬럼 | 표시 |
|---|---|
| 고객사명 | `clientName` |
| Prefix | `keyPrefix` (예: `ak_AbCdEfGh`) |
| 만료일 | `expiresAt` 포맷팅, 없으면 `—` |
| 마지막 사용 | `lastUsedAt` 포맷팅 |
| 상태 | 활성(초록) / 만료(회색) / 폐기됨(빨강) 칩 |
| 액션 | 활성일 때만 `폐기` 버튼 |

### 8.3 새 키 발급 폼

- 입력: `clientName` (필수), `description` (선택), `expiresAt` (date picker, 선택)
- 제출 → `POST /api/v1/agent-api-keys`

### 8.4 발급 결과 모달 (1회 노출)

```
✅ Agent API 키가 발급되었습니다.

이 정보는 이 창을 닫으면 다시 볼 수 없습니다.
지금 고객사에 안전하게 전달하세요.

API Key:
ak_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx          [복사]

Secret Key:
yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy    [복사]

[확인]
```

- `role="dialog" aria-modal="true"`, ESC/오버레이 닫기는 노출 보호 위해 비활성. **확인 버튼만 닫음**.
- 두 개의 복사 버튼 각각 `navigator.clipboard.writeText(...)` 호출.

### 8.5 폐기 확인 다이얼로그

`window.confirm`. 메시지: "이 키를 폐기하면 해당 고객사의 모든 Agent 요청이 즉시 검증 실패합니다. 진행하시겠습니까?"

### 8.6 에러 UI

상단 `role="alert"` 영역에 한글 메시지. 기존 `InternalApiKeysPage` / `LayerSettingsPage` 와 동일 패턴.

## 9. 테스트 전략

### 9.1 백엔드

**`SecretCipherTest` (단위)**
- 라운드트립 (encrypt → decrypt → 원문 일치)
- 같은 평문도 매 호출 IV 다름 → 암호문 다름
- 태그 변조 시 `AEADBadTagException`
- 빈 문자열 라운드트립

**`AgentApiKeyControllerTest` (MockMvc)**
- 발급 → 201 + apiKey/secret 평문 응답 + DB에는 hash/암호문만
- 발급 응답의 apiKey가 `ak_` + 32자 (= 35자)
- 발급 응답의 secret이 43자 base64url
- 발급 → `AGENT_KEY_CREATE` 감사 로그
- 목록 응답에 apiKey/apiKeyHash/secret 절대 미노출, keyPrefix 노출
- 빈 clientName → 400, 감사 로그 없음
- 과거 expiresAt → 400
- revoke → 200 + revokedAt 채워짐 + `AGENT_KEY_REVOKE` 감사 로그
- revoke 멱등 (두 번째 호출은 200 + revokedAt 변경 X + 감사 로그 추가 안 됨)

**`VerifyControllerTest` (MockMvc, 통합)**
- Fixture: 유효 Agent 키 발급 + 활성 Policy 1개 + 유효 InternalApiKey 발급 (`X-API-Key: iak_...` 헤더용)
- 정상 서명 → 200 `valid:true` + clientName + agentKeyId + policy 객체 + `AGENT_AUTH success=true` 감사 로그 + lastUsedAt 갱신
- 잘못된 서명 → `valid:false reason:invalid_signature`
- timestamp 너무 오래됨 (-1000초) → `reason:timestamp_skew`
- timestamp 너무 미래 (+1000초) → `reason:timestamp_skew`
- timestamp non-numeric → `reason:timestamp_skew`
- 모르는 apiKey → `reason:unknown_key`
- 폐기된 키 → `reason:revoked`
- 만료된 키 → `reason:expired`
- 활성 정책 없음 → `reason:no_active_policy`
- 필드 누락 (예: signature 없음) → 400
- `X-API-Key` (InternalApiKey) 헤더 누락 → 401 (기존 InternalApiKeyFilter)

**`PolicyControllerTest` 영향 없음** — `/policies/active` 는 `GatewayPolicyController` 측에 있었고, 이번에 제거되면 `GatewayPolicyControllerTest` 자체를 `/verify` 시나리오로 갈아끼움.

### 9.2 프론트엔드

**`AgentApiKeysPage.test.tsx`**
- 마운트 시 목록 fetch 후 렌더링
- 활성 키와 폐기된 키 칩 구분
- 새 키 발급 폼 제출 → POST 호출 + 모달에 apiKey/secret 두 줄 노출
- API Key 복사 버튼 → `clipboard.writeText(apiKey)` 호출
- Secret 복사 버튼 → `clipboard.writeText(secret)` 호출
- 확인 버튼 → 모달 닫힘
- 폐기 버튼 → confirm → POST `/{id}/revoke`
- 로딩 실패 → `role="alert"` 메시지

## 10. Docker / 운영 배포 변경

- `docker-compose.yml`:
  - `admin-backend` 서비스에 KeyStore 볼륨 마운트 + 환경변수 3종 (KeyStore path / password / alias)
  - 호스트 측 `admin-backend/config/aag-keystore.p12` 는 운영자가 사전 생성. **git ignore** 등록.
- `.gitignore` 에 `admin-backend/config/*.p12` 추가 (단 `src/test/resources/test-keystore.p12` 는 예외 경로라 영향 없음)
- 첫 배포 시 운영자가 `keytool` 로 KeyStore 생성 → 비밀번호를 `.env` 또는 별도 시크릿 채널로 등록. 가이드는 README 별도.

## 11. 비목표

- Agent 자체 등록(이름/이메일/SLA 등) 별도 리소스 — 이번엔 키 단위 식별만 (clientName 자유 입력)
- HMAC 외 다른 알고리즘 (OAuth, JWT) 지원
- Nonce 중복 검증 (Gateway 책임)
- 외부 Vault/KMS 연동 — KeyStore + 환경변수면 MVP 충분
- KeyStore 자동 로테이션 / 다중 키 alias 지원
- Agent별 사용량/요금 모니터링
- Agent별 정책 분리 — 현재 모든 Agent가 동일 활성 정책 적용
- `AGENT_AUTH` 감사 로그의 비동기/샘플링 — MVP는 전건 동기 기록
- HTTPS 강제 / mTLS — 인프라 레이어 책임
