"""보안 정책 Pydantic 모델."""

from pydantic import BaseModel


class LayerConfig(BaseModel):
    """단일 보안 레이어 설정 모델.

    Attributes:
        enabled: 레이어 활성화 여부.
    """

    enabled: bool


class GuardrailPolicy(BaseModel):
    """6개 보안 레이어의 활성화 여부를 담는 정책 모델.

    Attributes:
        layer_1_prompt_injection: 프롬프트 인젝션 탐지 레이어.
        layer_2_sensitive_data: 민감 데이터 탐지 레이어.
        layer_3_toxicity: 유해 콘텐츠 탐지 레이어.
        layer_4_hallucination: 환각 탐지 레이어.
        layer_5_pii: 개인정보 탐지 레이어.
        layer_6_compliance: 규정 준수 검사 레이어.
    """

    layer_1_prompt_injection: LayerConfig
    layer_2_sensitive_data: LayerConfig
    layer_3_toxicity: LayerConfig
    layer_4_hallucination: LayerConfig
    layer_5_pii: LayerConfig
    layer_6_compliance: LayerConfig
