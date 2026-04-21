# 헤더 값 추가 및 검증

## 1. Gateway에게 prompt를 전송하는 사용자는 앞으로 헤더 값 4개를 추가로 전송해요.
사용자는 API Request를 요청할 때 `X-API-Key`, `X-Timestamp`, `X-Nonce`, `X-Signature`를 함께 전송해요.

각 값의 의미는 다음과 같아요
| 헤더 | 설명 |
|-------|----------------|
| `X-API-Key` | 사용자가 ADMIN에게 미리 발급받은 API_KEY (미리 설정된 값으로 고정) |
| `X-Timestamp` | Unix epoch 초 (ms 아님). 서버 시간과 5분 (혹은 정책) 만큼 차이가 날 경우 차단 |
| `X-Nonce` | 요청마다 랜덤 |
| `X-Signature` | HMAC-SHA256(SECRET, `"{timestamp}.{nonce}.{sha256(body)}"`).  소문자 hex 64글자 |

## 2. 입력받은 헤더 4개에 대해 검증을 진행해요.
gateway-backend는 `X-Nonce`에 대해 Replay Attack을 방지하고자 검증하고, `X-Timestamp`에 대해 설정된 시간 만큼 차이가 날 경우 차단하고자 검증을 진행해요.

여기서 오류가 발생했을 경우, 로그에 차단 이유를 출력하고 사용자에게도 에러 처리하여 반환해요.

## 3. ADMIN에게 정책을 요청할 때, 앞으로 body에는 사용자의 헤더 값을 포함하여 body로 전송하여 검증을 진행해요.
앞으로는 어드민에게 정책을 요청할 때, 사용자 검증을 위한 값까지 한번에 전달하여 ADMIN에서 검증을 진행해요.

ADMIN의 주소는 `.env`의 `ADMIN_BACKEND_URL`를 참고하고, API PATH는 `/api/v1/gateway/verify`에요.
body에는 json 형태로 다음 데이터를 담아야해요.
```json
{
  "apiKey": "string",
  "timestamp": "string",
  "nonce": "string",
  "bodyHash": "string",
  "signature": "string"
}
```
각 필드의 설명은 다음과 같아요.
| 키 | 설명 |
|-------|----------------|
| `apiKey` | 사용자가 전달한 헤더의 `X-API-Key` 값을 그대로 전송 |
| `timestamp` | 사용자가 전달한 헤더의 `X-Timestamp` 값을 그대로 전송 | 
| `nonce` | 사용자가 전달한 헤더의 `X-Nonce` 값을 그대로 전송 |
| `bodyHash` | 사용자가 전달한 body 데이터에 대해 `sha256(body)`처리 하여 제출 |
| `signature` | 사용자가 전달한 헤더의 `X-Signature` 값을 그대로 전송 | 

그리고 헤더에는 `X-API-Key` 값으로, `.env`에 있는 `ADMIN_API_KEY`를 함께 제출해요. 이 값은 사용자의 API-KEY 값과 달리, Gateway 프로젝트가 ADMIN에게 미리 받은 키 값이에요.
