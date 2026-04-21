# Solar API 502 대응 수정 계획

## 배경

`/playground/`에서 메시지를 전송하면 `502 Bad Gateway`가 반환된다.
코드와 런타임 경로를 점검한 결과, 현재 증상은 게이트웨이 내부 라우팅 오류라기보다
Solar upstream 오류가 부정확하게 매핑되어 나타나는 상황이다.

확인된 사실:

- `admin-backend` 정책 조회는 정상 응답(`200 OK`)
- Solar 직접 호출은 실패
- 실제 upstream 오류는 `401 AuthenticationError`
- 오류 본문에는 `api_key_is_not_allowed`와
  `API key suspended due to insufficient credit`가 포함됨
- 게이트웨이는 현재 Solar 관련 `openai.APIError`를 일괄 `502`로 변환함

즉, 1차 원인은 Upstage 계정/결제/크레딧 상태이고, 2차 문제는 게이트웨이의
오류 매핑과 관측성이 부족해 실제 원인을 식별하기 어렵다는 점이다.

## 목표

- Solar 장애 원인을 클라이언트와 운영자가 즉시 식별할 수 있게 한다.
- 인증 실패, 쿼터 초과, 연결 실패, 타임아웃을 서로 다른 HTTP 상태로 구분한다.
- Solar뿐 아니라 `admin-backend` 연동 실패도 동일한 수준으로 구조화한다.
- 성공 응답 스키마는 유지하고, 오류 응답만 명확하게 개선한다.

## 현재 문제 요약

### 1. Solar 4xx가 전부 502로 숨겨짐

현재 구현은 `openai.APIError` 전체를 하나의 전역 예외 핸들러로 처리한다.
이 때문에 인증 실패(`401`), 잘못된 요청(`400`), rate limit(`429`)까지도 모두
`502`로 노출된다.

영향:

- `playground` 사용자는 서버 장애로 오해하기 쉽다.
- 운영자는 Solar 인증/결제 문제를 즉시 구분하기 어렵다.
- 외부 클라이언트는 재시도 가능 여부를 판단하기 어렵다.

### 2. admin-backend 실패는 구조화되어 있지 않음

정책 조회는 요청마다 선행되지만, `httpx.HTTPError` 계열 예외를 별도 매핑하지
않아 기본 `500`으로 노출될 수 있다.

영향:

- Solar 오류와 정책 조회 오류가 일관되게 표현되지 않는다.
- 운영 관점에서 upstream 장애 위치를 바로 알기 어렵다.

### 3. 관측성과 진단 정보가 부족함

현재 상태로는 세션 ID, 모델명, upstream 상태코드, provider 오류 코드가
구조적으로 남지 않는다.

영향:

- 동일 증상을 재현해도 원인 분류가 늦다.
- 로그 기반 운영과 장애 대응이 어렵다.

## 수정 범위

이번 수정 범위는 다음으로 제한한다.

- Solar 예외 매핑 개선
- `admin-backend` 예외 매핑 추가
- 오류 응답 JSON 구조화
- 로그/관측성 보강
- `playground` 오류 표시 개선
- 해당 동작을 검증하는 테스트 추가

이번 수정 범위에 포함하지 않는 항목:

- 가드레일 비즈니스 로직 변경
- 보안 레이어 구현 교체
- 모델 라우팅 정책 변경
- 인증/결제 상태 자체를 코드로 우회하는 처리

## 설계 방향

### 1. Solar 예외를 원인별로 분리 매핑

기본 원칙:

- upstream `4xx`는 가능한 한 의미를 보존한다.
- 네트워크 계층 장애만 `502/504`로 매핑한다.
- 사용자가 조치 가능한 오류와 서버 측 일시 장애를 구분한다.

권장 매핑:

| 예외/상황 | 반환 상태코드 | 의미 |
| --- | --- | --- |
| `AuthenticationError` | `401` | API 키 무효, 정지, 결제/크레딧 문제 |
| `BadRequestError` | `400` | 요청 파라미터 오류 |
| `PermissionDeniedError` | `403` | 권한 부족 |
| `NotFoundError` | `404` | 모델/리소스 없음 |
| `ConflictError` | `409` | 충돌 상태 |
| `UnprocessableEntityError` | `422` | 형식은 맞지만 처리 불가 |
| `RateLimitError` | `429` | 호출 한도 또는 쿼터 초과 |
| `APITimeoutError` | `504` | upstream 타임아웃 |
| `APIConnectionError` | `502` | 연결 실패/DNS/TLS/네트워크 오류 |
| `InternalServerError` 및 기타 Solar 5xx | `502` 또는 `503` | upstream 내부 장애 |
| 기타 `APIError` | 가능하면 upstream status 유지, 없으면 `502` | 일반 fallback |

추가 원칙:

- `retryable` 여부를 응답에 포함해 클라이언트 재시도 판단에 도움을 준다.
- 인증 실패와 크레딧 부족은 `retryable=false`로 본다.
- 연결 실패, 타임아웃, Solar 5xx는 기본 `retryable=true`로 본다.

### 2. 오류 응답을 구조화

성공 응답은 유지하고, 오류 응답만 다음 필드를 공통 제공한다.

```json
{
  "detail": "Solar 인증 실패",
  "provider": "solar",
  "upstream_status": 401,
  "upstream_code": "api_key_is_not_allowed",
  "retryable": false
}
```

필드 원칙:

- `detail`: 사용자/운영자가 읽을 수 있는 요약 메시지
- `provider`: `"solar"` 또는 `"admin_backend"`
- `upstream_status`: 원래 upstream 상태코드
- `upstream_code`: provider가 제공한 코드가 있으면 포함
- `retryable`: 재시도 가치가 있는지 여부

호환성 원칙:

- 기존 클라이언트를 위해 `detail` 필드는 유지한다.
- 성공 응답 스키마는 변경하지 않는다.

### 3. admin-backend 오류도 같은 기준으로 매핑

정책 조회 실패 시에도 upstream 위치와 유형이 식별 가능해야 한다.

권장 매핑:

| 상황 | 반환 상태코드 | provider |
| --- | --- | --- |
| 연결 실패 | `503` | `admin_backend` |
| 타임아웃 | `504` | `admin_backend` |
| upstream `4xx/5xx` | 원인 보존 또는 `503` | `admin_backend` |

핵심은 Solar 장애와 정책 조회 장애가 같은 형태의 구조화된 JSON으로
노출되도록 맞추는 것이다.

### 4. 관측성 보강

로그에 다음 정보를 남긴다.

- 세션 ID
- provider 이름
- 요청 모델명
- base URL
- 예외 타입
- upstream 상태코드
- upstream 오류 코드

로그 금지 항목:

- API 키
- 전체 프롬프트 본문
- 민감 응답 전문

목표:

- 사용자 제보 없이도 로그만으로 장애 유형을 재분류할 수 있게 한다.
- 재현이 어려운 간헐 장애도 분류 가능한 최소 정보를 확보한다.

### 5. playground 오류 표시 개선

`playground`는 이미 오류 본문을 그대로 보여주고 있으므로, 서버가 구조화된
JSON을 반환하면 다음 정보를 분리 노출하는 방향이 적절하다.

- HTTP status
- provider
- upstream_status
- upstream_code
- detail

효과:

- 사용자가 `502`만 보고 네트워크 장애로 오해하지 않는다.
- 운영자 없이도 인증/결제/쿼터/타임아웃을 1차 분류할 수 있다.

## 구현 순서

1. Solar 예외 매핑 규칙을 정리하고 공통 오류 응답 포맷을 정의한다.
2. 전역 예외 처리 또는 별도 매퍼에서 Solar 예외를 세분화한다.
3. `admin-backend`용 `httpx` 예외 매핑을 추가한다.
4. provider별 구조화된 오류 JSON을 반환하도록 정리한다.
5. 필요한 로그 필드를 추가한다.
6. `playground`가 구조화된 오류 필드를 읽어 표시하도록 보강한다.
7. 예외 매핑 테스트와 `playground` 회귀 테스트를 추가한다.

## 테스트 계획

### Solar 예외 매핑

- `AuthenticationError` -> `401`
- `BadRequestError` -> `400`
- `PermissionDeniedError` -> `403`
- `NotFoundError` -> `404`
- `ConflictError` -> `409`
- `UnprocessableEntityError` -> `422`
- `RateLimitError` -> `429`
- `APIConnectionError` -> `502`
- `APITimeoutError` -> `504`
- `InternalServerError` -> `502` 또는 `503`

검증 포인트:

- `detail` 포함
- `provider="solar"`
- `upstream_status` 정확성
- `upstream_code` 전달 여부
- `retryable` 판정 정확성

### admin-backend 예외 매핑

- 연결 실패 -> `503`
- 타임아웃 -> `504`
- upstream `4xx/5xx` -> 설계한 상태코드 반환

검증 포인트:

- `provider="admin_backend"`
- 구조화된 오류 JSON 형식 유지

### 라우터/플레이그라운드 회귀

- `/v1/chat/completions` 성공 응답 유지
- `stream=false` 성공 경로 유지
- `stream=true` 성공 경로 유지
- 오류 시 `playground`가 구조화된 JSON을 사람이 읽기 좋은 형태로 출력

## 운영 측 즉시 조치

코드 수정과 별개로, 현재 운영 상태에서 우선 처리해야 할 항목은 다음이다.

1. Upstage 콘솔에서 결제 수단과 크레딧 상태 확인
2. 정지되지 않은 API 키로 교체 가능 여부 확인
3. 사용 중인 모델(`solar-pro3-260323`) 접근 권한 확인

이 조치를 하지 않으면, 코드 개선 이후에도 Solar 호출 자체는 계속 실패할 수 있다.

## 기대 효과

- 현재와 같은 Solar 인증/결제 문제를 `502`가 아닌 실제 원인에 가깝게 노출
- 운영자와 사용자가 장애 원인을 더 빠르게 분류 가능
- 재시도 가능한 오류와 불가능한 오류를 구분 가능
- `playground`가 단순 테스트 도구를 넘어 진단 도구 역할을 수행

## 결정 및 가정

- 게이트웨이는 OpenAI 호환 프록시 성격이 강하므로 upstream `4xx`는 가능한 한
  보존하는 방향을 택한다.
- 성공 응답 스키마는 유지하고 오류 응답만 구조화한다.
- 현재 가장 시급한 운영 원인은 코드 버그가 아니라 Upstage 계정 상태다.
