"""보안 정책 Pydantic 모델."""

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field


class L5Setting(BaseModel):
    """ADMIN 이 전달하는 L5 모델 선택/판정 설정.

    Attributes:
        model: L5 NER 모델 폴더명. 예: `pii_model_v11`.
        threshold: NER 엔티티 스코어 컷오프. `L5Layer.min_score` 로 전달된다.
    """

    model_config = ConfigDict(extra="ignore")

    model: str | None = None
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)


class GuardrailPolicy(BaseModel):
    """admin-backend가 제공하는 L1~L6 보안 레이어 활성화 정책.

    admin API(`/api/v1/policies/active`) 응답의 `l1Enabled`..`l6Enabled`
    와 `outboundEnabled` 필드를 그대로 수신할 수 있도록 alias를 사용한다.
    그 외 메타 필드(name, description, id, isUse, createdAt 등)는 무시한다.

    Attributes:
        l1: 프롬프트 인젝션 탐지 레이어 활성화 여부.
        l2: 민감 데이터 탐지 레이어 활성화 여부.
        l3: 유해 콘텐츠 탐지 레이어 활성화 여부.
        l4: 환각 탐지 레이어 활성화 여부.
        l5: 개인정보 탐지 레이어 활성화 여부.
        l5_setting: 개인정보 탐지 레이어의 모델 폴더명과 NER threshold.
        l6: 규정 준수 검사 레이어 활성화 여부.
        outbound: LLM 응답에 대한 출력 가드레일 파이프라인 전체 스위치.
            False 이면 L1~L6 활성 레이어와 무관하게 출력 검사를 통째로
            생략한다. ADMIN 응답에 키가 없으면 기존 동작(출력 검사 수행)을
            유지하도록 기본값은 True.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    l1: bool = Field(alias="l1Enabled")
    l2: bool = Field(alias="l2Enabled")
    l3: bool = Field(alias="l3Enabled")
    l4: bool = Field(alias="l4Enabled")
    l5: bool = Field(alias="l5Enabled")
    l5_setting: L5Setting | None = Field(default=None, alias="l5Setting")
    l6: bool = Field(alias="l6Enabled")
    outbound: bool = Field(default=True, alias="outboundEnabled")

    @classmethod
    def all_disabled(cls) -> GuardrailPolicy:
        """모든 레이어와 출력 파이프라인이 비활성인 정책을 반환한다.

        Returns:
            L1~L6 과 `outbound` 가 전부 False인 GuardrailPolicy 인스턴스.
        """
        return cls(
            l1=False,
            l2=False,
            l3=False,
            l4=False,
            l5=False,
            l6=False,
            outbound=False,
        )

    @classmethod
    def all_enabled(cls) -> GuardrailPolicy:
        """L1~L6 전부와 출력 파이프라인이 활성인 정책을 반환한다.

        `SKIP_POLICY_FETCH=true` 설정 시 admin-backend 조회를 생략하면서도
        모든 가드레일 레이어를 강제로 실행하기 위해 사용한다.

        Returns:
            L1~L6 과 `outbound` 가 전부 True인 GuardrailPolicy 인스턴스.
        """
        return cls(
            l1=True,
            l2=True,
            l3=True,
            l4=True,
            l5=True,
            l6=True,
            outbound=True,
        )

    @classmethod
    def from_layer_indices(
        cls,
        layers: Iterable[int],
        *,
        outbound: bool,
        l5_setting: L5Setting | None = None,
    ) -> GuardrailPolicy:
        """레이어 인덱스 셋과 outbound 플래그로 정책을 만든다.

        SKIP_POLICY_FETCH 보조 환경변수(`SKIP_POLICY_FETCH_INPUT_LAYERS` /
        `SKIP_POLICY_FETCH_OUTPUT_LAYERS`)에서 파싱된 인덱스 집합을 그대로
        정책 객체로 변환하기 위한 팩토리. admin-backend 응답을 거치지 않아도
        환경변수 기반 L5 설정을 전달할 수 있다.

        Args:
            layers: 활성화할 레이어 인덱스의 iterable. 1~6 범위만 허용.
                중복은 무시된다.
            outbound: 출력 가드레일 파이프라인 활성화 여부. 빈 인덱스 셋과
                outbound=False 를 함께 넘기면 출력 검사가 통째로 생략된다.
            l5_setting: L5 모델 폴더명과 threshold 설정. None 이면 기본
                L5 레이어 설정을 사용한다.

        Returns:
            지정한 레이어만 활성화된 GuardrailPolicy 인스턴스.

        Raises:
            ValueError: 1~6 외 인덱스가 포함된 경우.
        """
        wanted = set(layers)
        invalid = {idx for idx in wanted if idx not in {1, 2, 3, 4, 5, 6}}
        if invalid:
            raise ValueError(
                f"layer 인덱스는 1~6 만 허용됩니다. 잘못된 값: "
                f"{sorted(invalid)}"
            )
        return cls(
            l1=1 in wanted,
            l2=2 in wanted,
            l3=3 in wanted,
            l4=4 in wanted,
            l5=5 in wanted,
            l5_setting=l5_setting,
            l6=6 in wanted,
            outbound=outbound,
        )

    def enabled_layers(self) -> list[int]:
        """활성화된 레이어 인덱스 목록을 반환한다.

        Returns:
            활성 레이어 인덱스 리스트 (예: [1, 3, 5]).
        """
        flags = [self.l1, self.l2, self.l3, self.l4, self.l5, self.l6]
        return [idx + 1 for idx, enabled in enumerate(flags) if enabled]
