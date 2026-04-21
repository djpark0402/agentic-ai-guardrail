# 가드레일 core 연계 정보

## 레이어별 Request, Response 모델
```python
@dataclass(frozen=True)
class GuardrailRequest:
    """가드레일 체인에 전달되는 불변 요청 객체.

    Attributes:
        user_input: 사용자가 제출한 원본 프롬프트.
        session_id: 멀티턴 대화 세션 식별자.
        metadata: API 키, 모델명 등 추가 컨텍스트.
    """

    user_input: str
    session_id: str | None = None
    metadata: dict[str, Any] | None = None

@dataclass
class LayerResult:
    """단일 가드레일 레이어의 검사 결과.

    Attributes:
        name: 레이어 식별자 (예: ``"L1"``).
        allowed: 요청의 계속 진행 허용 여부.
        reason: ``allowed`` 가 ``False`` 일 때의 사유.
        severity: 차단 판정의 심각도 수준.
        confidence: 판정 신뢰도 (0.0~1.0).
        execution_time_ms: 레이어 실행 소요 시간(밀리초).
        tags: 분류 태그 (예: ``["xss", "injection"]``).
    """

    name: str
    allowed: bool
    reason: str | None = None
    severity: Severity = Severity.NONE
    confidence: float = 1.0
    execution_time_ms: float | None = None
    tags: list[str] = field(default_factory=list)
```

## 실사용 방법

```python
# Request
# 1) 최소 — 단건 API 호출
GuardrailRequest(user_input="오늘 날씨 알려줘")

# 2) 세션 있는 멀티턴 대화
GuardrailRequest(
    user_input="아까 말한 내용 요약해줘",
    session_id="sess-abc-123", # optional
)

# 3) 풀 컨텍스트 — gateway-backend가 전달하는 메타데이터 포함
GuardrailRequest(
    user_input="회사 매출 데이터 보여줘",
    session_id="sess-abc-123", # optional
    metadata={                 # optional
        "model": "gpt-4",
        "api_key": "key-xxxx",
        "client_ip": "192.168.1.10",
        "timestamp": 1744819200,
    },
)
```

```python
# Result
# 1) 규칙 기반 레이어 — 통과
LayerResult(name="L1", allowed=True, confidence=1.0)

# 2) 규칙 기반 레이어 — 차단 (XSS 탐지)
LayerResult(
    name="L1",
    allowed=False,
    reason="forbidden token: <script>",
    severity=Severity.CRITICAL,
    confidence=0.0,
    tags=["xss", "html_injection"],
)

# 3) ML 기반 레이어 — 차단 (프롬프트 인젝션, 92% 확신)
LayerResult(
    name="L3",
    allowed=False,
    reason="prompt injection detected",
    severity=Severity.HIGH,
    confidence=0.92,
    tags=["prompt_injection"],
)

# 4) ML 기반 레이어 — 통과 (낮은 위험)
LayerResult(
    name="L3",
    allowed=True,
    severity=Severity.NONE,
    confidence=0.85,
)
```

```python
# 실사용
from core_secure_layer.layers.types import (
    GuardrailRequest,
    GuardrailResponse,
    Severity,
)
from core_secure_layer.layers.l1.l1 import L1Layer

# input
request = GuardrailRequest(user_input="회사 매출 데이터 보여줘")

# 레이어 init
layers = L1Layer()

# 실행
result = await layer.check(request)

# output
LayerResult(
    name="L1",
    allowed=True,
    reason=None,
    severity=Severity.NONE,
    confidence=1.0,
    execution_time_ms=0.35,
    tags=[],
)
```