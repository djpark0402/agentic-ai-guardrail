# Internal API Key 기능 설계

## 1. 배경 및 목적

Admin 서버와 Guardrail(Gateway) 서버는 서로 다른 프로세스로 동작하며, Gateway가 Admin의 특정 엔드포인트(예: 현재 활성 정책 조회)를 호출해야 한다. 이 서비스 간 호출에 대한 인증 수단으로 **Internal API Key**를 도입한다.

- Admin이 키를 발급·관리한다.
- Gateway 운영자는 발급된 키를 저장했다가 Admin 호출 시 헤더로 함께 전송한다.
- Admin은 각 Gateway 전용 엔드포인트에서 헤더를 검증한다.
- 관리자 UI용 엔드포인트는 이번 범위 밖이며, 장래에 관리자 로그인이 붙을 슬롯만 마련한다.

## 2. 범위

본 문서는 **Admin 백엔드(Spring Boot)와 Admin 프론트엔드(React)만** 다룬다. Gateway 측 구현은 별도이며, 발급된 평문 키를 `X-API-Key` 헤더로 전송한다는 계약만 공유한다.

## 3. 아키텍처

### 3.1 URL 규약

| 경로 prefix | 용도 | 보호 |
|---|---|---|
| `/api/v1/gateway/**` | Gateway 전용 호출 | `X-API-Key` 필수 |
| `/api/v1/internal-api-keys/**` | 키 CRUD (Admin UI) | 현재 프리패스, 장래 관리자 인증 슬롯 |
| `/api/v1/**` (그 외) | Admin UI용 (Policy, AuditLog 등) | 현재 프리패스, 장래 관리자 인증 슬롯 |
| `/swagger-ui/**`, `/v3/api-docs/**` | API 문서 | permitAll |

기존 `GET /api/v1/policies/active`는 `GET /api/v1/gateway/policies/active`로 이동한다.

### 3.2 Spring Security Filter Chain

```
SecurityFilterChain
 ├─ "/api/v1/gateway/**"  → InternalApiKeyFilter 적용
 ├─ "/api/v1/**"          → permitAll()  (※ 향후 AdminAuthFilter 슬롯)
 └─ "/swagger-ui/**",
    "/v3/api-docs/**"     → permitAll()
```

`InternalApiKeyFilter`는 `OncePerRequestFilter`를 상속하여:
1. `X-API-Key` 헤더 읽기 (없으면 401)
2. SHA-256 해시 계산 → `internal_api_keys` 테이블에서 `key_hash` 일치 + `revoked_at IS NULL` + (`expires_at IS NULL OR expires_at > now()`) 행 조회
3. 없으면 401 + 감사로그(`APIKEY_AUTH`, `success=false`)
4. 있으면 `last_used_at = now()` 갱신 + 감사로그(`APIKEY_AUTH`, `success=true`) + 체인 진행

## 4. 데이터 모델

### 4.1 `internal_api_keys` 테이블

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | BIGINT | PK, AUTO_INCREMENT | |
| `name` | VARCHAR(100) | NOT NULL | 키 용도 (예: `gateway-prod-01`) |
| `description` | VARCHAR(500) | NULL | 선택 설명 |
| `key_prefix` | VARCHAR(12) | NOT NULL | 평문 앞 12자 (`iak_` + 랜덤 8자, UI 식별용) |
| `key_hash` | VARCHAR(64) | NOT NULL, UNIQUE | SHA-256 hex |
| `expires_at` | TIMESTAMP | NULL | null = 무기한 |
| `revoked_at` | TIMESTAMP | NULL | null = 활성 |
| `last_used_at` | TIMESTAMP | NULL | 마지막 성공 검증 시각 |
| `created_at` | TIMESTAMP | NOT NULL | |
| `updated_at` | TIMESTAMP | NOT NULL | |

### 4.2 키 포맷

- 평문: `iak_<base64url(24 bytes random)>` → `iak_` (4자) + 32자 = **총 36자**, 192비트 엔트로피
- `iak_` prefix는 로그/코드 검색과 실수 노출 방지 식별자
- 저장: `SHA-256(plain)` hex. 랜덤 엔트로피가 높으므로 bcrypt 불필요.

### 4.3 활성 판단

```sql
revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now())
```

### 4.4 로테이션

별도 rotate 엔드포인트 없음. 운영 절차:
1. 새 키 발급 → Gateway에 배포
2. 구키 revoke

다건 활성을 허용하므로 유예 기간 동안 구키/신키 공존 가능.

## 5. API 명세

### 5.1 Admin UI용 (`/api/v1/internal-api-keys`)

| 메서드 | 경로 | 요청 | 응답 |
|---|---|---|---|
| POST | `/` | `{name, description?, expiresAt?}` | `201 Created`, body = 메타 + **`plainKey`** (이 응답에만) |
| GET | `/` | — | `[{id, name, description, keyPrefix, expiresAt, revokedAt, lastUsedAt, createdAt, updatedAt}]` |
| GET | `/{id}` | — | 목록 단건 스키마 동일 |
| POST | `/{id}/revoke` | — | 단건 스키마 (`revokedAt` 채워짐) |

- `name`: NotBlank, 최대 100자
- `description`: 최대 500자
- `expiresAt`: ISO-8601 UTC, 과거 시각이면 400
- 이미 revoke 된 키에 다시 revoke 요청 → 멱등하게 200 + 기존 `revokedAt` 유지

### 5.2 Gateway 전용 (`/api/v1/gateway/**`)

| 메서드 | 경로 | 인증 | 비고 |
|---|---|---|---|
| GET | `/api/v1/gateway/policies/active` | `X-API-Key` 필수 | 기존 `/policies/active`에서 이동 |

## 6. 감사 로그

### 6.1 `Action` enum 확장

```java
APIKEY_CREATE("내부 API 키 생성"),
APIKEY_REVOKE("내부 API 키 폐기"),
APIKEY_AUTH("Gateway 인증 시도"),
```

### 6.2 `ActorType` 매핑

| 이벤트 | ActorType | Action | success |
|---|---|---|---|
| 관리자 키 생성 | `ADMIN` | `APIKEY_CREATE` | true |
| 관리자 키 폐기 | `ADMIN` | `APIKEY_REVOKE` | true |
| Gateway 인증 성공 | `GATEWAY` | `APIKEY_AUTH` | true |
| Gateway 인증 실패 | `GATEWAY` | `APIKEY_AUTH` | false |

### 6.3 `detail` 형식

- 관리자 이벤트: `"id=<id>, name=<name>, keyPrefix=<prefix>"`
- 인증 성공: `"keyPrefix=<prefix>, name=<name>"`
- 인증 실패: `"invalid key: prefix=<prefix>"` (평문 미기록, prefix만)
- 인증 실패(헤더 누락): `"missing X-API-Key header"`

## 7. 프론트엔드 UI

### 7.1 페이지 & 라우트

- 새 페이지: `InternalApiKeysPage` (`src/pages/InternalApiKeysPage.tsx`)
- 라우트: `/admin/internal-api-keys`
- 사이드바 메뉴 순서: Layer 설정 / 감사 로그 / **Internal API 키** (신규)

### 7.2 주요 컴포넌트

**1) 키 목록 테이블**

| 컬럼 | 표시 |
|---|---|
| 이름 | `name` |
| Prefix | `keyPrefix` (예: `iak_AbCd`) |
| 만료일 | `expiresAt` 포맷팅, 없으면 `—` |
| 마지막 사용 | `lastUsedAt` 포맷팅 |
| 상태 | 활성(초록) / 만료(회색) / 폐기됨(빨강) 칩 |
| 액션 | 활성일 때만 `폐기` 버튼 |

**2) 새 키 발급 폼 (모달 또는 인라인)**

- 입력: `name` (필수), `description` (선택), `expiresAt` (date picker, 선택)
- 제출 → `POST /api/v1/internal-api-keys`

**3) 평문 키 노출 모달** (발급 직후 1회)

- 큰 코드블록에 `plainKey` 표시 + 복사 버튼
- 경고 문구: "이 창을 닫으면 다시 볼 수 없습니다. 지금 복사해서 Gateway 환경변수에 저장하세요."
- 확인 버튼 클릭 → 모달 닫힘, 목록 새로고침

**4) 폐기 확인 다이얼로그**

- `window.confirm` 또는 커스텀 다이얼로그
- 문구: "이 키를 폐기하면 해당 키로 접속하는 Gateway는 즉시 401을 받습니다. 진행하시겠습니까?"

### 7.3 에러 UI

- 로딩 실패 / 생성 실패 / 폐기 실패 각각 상단 알림 영역(`role="alert"`)에 한글 메시지 표시 (기존 `LayerSettingsPage` 스타일 일관성 유지)

## 8. 테스트 전략

### 8.1 백엔드

**`InternalApiKeyControllerTest` (MockMvc)**
- `createKey_returns201_withPlainKey_and_writesAudit`: 생성 시 201 + plainKey 포함 + keyHash 미노출 + `APIKEY_CREATE` 감사로그
- `listKeys_neverIncludesPlainKey`: 목록에 `plainKey` 필드 없음
- `getKey_returns404_whenNotFound`
- `revokeKey_setsRevokedAt_andWritesAudit`
- `revokeKey_isIdempotent`: 두 번 revoke 해도 200 + `revokedAt` 변하지 않음
- `createKey_withBlankName_returns400`
- `createKey_withPastExpiresAt_returns400`

**`InternalApiKeyFilterTest` (SpringBootTest + MockMvc)**
- `gatewayEndpoint_withValidKey_returns200_andUpdatesLastUsedAt_andWritesSuccessAudit`
- `gatewayEndpoint_withoutHeader_returns401_andWritesFailAudit`
- `gatewayEndpoint_withUnknownKey_returns401`
- `gatewayEndpoint_withRevokedKey_returns401`
- `gatewayEndpoint_withExpiredKey_returns401`
- `nonGatewayEndpoint_isNotAffectedByFilter`: `/api/v1/policies` 목록은 필터 영향 없음

**기존 테스트 이동**
- `PolicyControllerTest`의 `activeEndpoint_*` 2개 → `/api/v1/gateway/policies/active` 경로 + 테스트 fixture로 유효 키 삽입 + 헤더 첨부로 변경

### 8.2 프론트엔드

**`InternalApiKeysPage.test.tsx` (vitest + testing-library)**
- 마운트 시 목록 fetch
- 새 키 폼 제출 → POST 호출 + 평문 노출 모달 표시
- 평문 노출 모달에 `plainKey` 텍스트가 정확히 렌더링됨
- 복사 버튼 클릭 시 `navigator.clipboard.writeText` 호출
- 폐기 버튼 클릭 → confirm 통과 시 `POST /{id}/revoke`
- 로딩 실패 시 오류 알림 표시
- 목록에 `plainKey`가 절대 포함되지 않음 확인 (API response 안에도 없으므로 렌더 불가)

## 9. 배포 및 마이그레이션

- Hibernate `ddl-auto: update`가 `internal_api_keys` 테이블을 자동 생성
- Docker 이미지 재빌드 필요 (백엔드 코드 변경)
- 기존 `/api/v1/policies/active` 경로를 호출하는 Gateway 측 코드는 **Gateway 팀이 `/api/v1/gateway/policies/active`로 수정** 필요. 본 PR 머지 전 사전 공유.

## 10. 비목표(Non-Goals)

- HMAC 서명 / nonce / 타임스탬프 검증 (Gateway의 기존 `security.py` 스타일). 단순 Bearer로 시작하고, 필요 시 별도 PR로 확장.
- 관리자 로그인/세션. 필터 체인에 슬롯만 마련.
- 키 자동 로테이션 / 만료 알림 / 사용량 제한.
- 키의 권한(scope) 구분. 모든 키는 Gateway 전용 엔드포인트에 동일 권한으로 통함.
