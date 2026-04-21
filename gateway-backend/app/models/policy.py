"""보안 정책 Pydantic 모델."""

from pydantic import BaseModel, ConfigDict, Field


class GuardrailPolicy(BaseModel):
    """admin-backend가 제공하는 L1~L6 보안 레이어 활성화 정책.

    admin API(`/api/v1/policies/active`) 응답의 `l1Enabled`..`l6Enabled`
    필드를 그대로 수신할 수 있도록 alias를 사용한다. 그 외 메타 필드
    (name, description, id, isUse, createdAt 등)는 무시한다.

    Attributes:
        l1: 프롬프트 인젝션 탐지 레이어 활성화 여부.
        l2: 민감 데이터 탐지 레이어 활성화 여부.
        l3: 유해 콘텐츠 탐지 레이어 활성화 여부.
        l4: 환각 탐지 레이어 활성화 여부.
        l5: 개인정보 탐지 레이어 활성화 여부.
        l6: 규정 준수 검사 레이어 활성화 여부.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    l1: bool = Field(alias="l1Enabled")
    l2: bool = Field(alias="l2Enabled")
    l3: bool = Field(alias="l3Enabled")
    l4: bool = Field(alias="l4Enabled")
    l5: bool = Field(alias="l5Enabled")
    l6: bool = Field(alias="l6Enabled")

    @classmethod
    def all_disabled(cls) -> GuardrailPolicy:
        """모든 레이어가 비활성인 기본 정책을 반환한다.

        Returns:
            L1~L6 전부 False인 GuardrailPolicy 인스턴스.
        """
        return cls(
            l1=False,
            l2=False,
            l3=False,
            l4=False,
            l5=False,
            l6=False,
        )

    @classmethod
    def all_enabled(cls) -> GuardrailPolicy:
        """L1~L6 전부가 활성인 정책을 반환한다.

        `SKIP_POLICY_FETCH=true` 설정 시 admin-backend 조회를 생략하면서도
        모든 가드레일 레이어를 강제로 실행하기 위해 사용한다.

        Returns:
            L1~L6 전부 True인 GuardrailPolicy 인스턴스.
        """
        return cls(
            l1=True,
            l2=True,
            l3=True,
            l4=True,
            l5=True,
            l6=True,
        )

    def enabled_layers(self) -> list[int]:
        """활성화된 레이어 인덱스 목록을 반환한다.

        Returns:
            활성 레이어 인덱스 리스트 (예: [1, 3, 5]).
        """
        flags = [self.l1, self.l2, self.l3, self.l4, self.l5, self.l6]
        return [idx + 1 for idx, enabled in enumerate(flags) if enabled]
