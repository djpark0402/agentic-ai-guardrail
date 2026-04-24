from unittest.mock import MagicMock

import pytest

from core_secure_layer.layers.l5.l5 import L5Layer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)


def _req(text):
    """주어진 텍스트로 GuardrailRequest 를 생성한다."""
    return GuardrailRequest(user_input=text)


def _new_layer(
    *,
    ner_model: object | None = None,
    extra_patterns: list[str] | None = None,
) -> L5Layer:
    """__init__ 을 우회해 L5Layer 인스턴스를 만드는 테스트용 팩토리.

    pii_labels.json / HF 파이프라인 로드 없이도 `_check_regex` /
    `_check_ner` 를 그대로 실행할 수 있도록 필수 속성을 모두 세팅한다.
    """
    inst = L5Layer.__new__(L5Layer)
    inst.name = "L5"
    inst.model_name = "ner-ko"
    inst.extra_patterns = list(extra_patterns or [])
    inst.min_score = 0.0
    inst.label_map = {}
    inst.block_singletons = frozenset()
    inst.aggregation_strategy = "simple"
    inst._block_combinations = ()
    inst._ner_model = ner_model
    return inst


@pytest.fixture
def layer():
    """NER 모델 미로드 상태의 L5Layer 인스턴스.

    Regex 1단계만 동작하고, NER 2단계는 fail-open 으로 허용.
    """
    return _new_layer(ner_model=None)


@pytest.fixture
def layer_with_extra():
    """extra_patterns 가 설정된 L5Layer 인스턴스.

    외부 주입 정규식 매칭 테스트용.
    """
    return _new_layer(ner_model=None, extra_patterns=[r"PROJ-\d{6}"])


@pytest.fixture
def layer_with_ner():
    """NER 모델이 로드된 상태의 L5Layer 인스턴스.

    _ner_predict 를 monkeypatch 하여 NER 결과를 제어한다.
    """
    return _new_layer(ner_model=MagicMock())


# ──────────────────────────────────────────────
# 0. 생성자 계약 검증
# ──────────────────────────────────────────────


class TestConstructorContract:
    """L5Layer 생성자가 필수 파라미터를 받는지 확인."""

    def test_accepts_all_params(self):
        # model_name 과 extra_patterns 를 전달할 수 있어야 한다
        inst = L5Layer(
            model_name="ner-ko",
            extra_patterns=[r"PROJ-\d{6}"],
        )
        assert inst.name == "L5"

    def test_default_extra_patterns_empty(self):
        # 기본 extra_patterns 는 빈 리스트
        inst = L5Layer(model_name="ner-ko")
        assert inst.extra_patterns == []

    def test_default_model_name(self):
        # model_name 기본값은 "ner-ko"
        inst = L5Layer()
        assert inst.name == "L5"
        assert inst.model_name == "ner-ko"


# ──────────────────────────────────────────────
# 1. 허용 골든 패스
# ──────────────────────────────────────────────


class TestAllowedGoldenPath:
    """정상 입력이 허용되는 기본 시나리오."""

    async def test_normal_korean_allowed(self, layer):
        # PII 가 없는 일반 한국어 문장 → 허용
        result = await layer.check(
            _req("오늘 날씨가 좋다"),
        )
        assert result.allowed is True
        assert result.name == "L5"
        assert result.reason is None

    async def test_normal_english_allowed(self, layer):
        # PII 가 없는 영문 문장 → 허용
        result = await layer.check(
            _req("Hello, how are you today?"),
        )
        assert result.allowed is True

    async def test_person_only_allowed(self, layer_with_ner, monkeypatch):
        # NER: PERSON 단독 감지 → 오탐 방지 → 허용
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {"entity": "PERSON", "word": "홍길동", "start": 0},
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("홍길동이 좋아한다"),
        )
        assert result.allowed is True
        assert result.reason is None

    async def test_empty_string_allowed(self, layer):
        # 빈 문자열 → 탐지 대상 없음 → 허용
        result = await layer.check(_req(""))
        assert result.allowed is True


# ──────────────────────────────────────────────
# 2. 차단 골든 패스 — Regex 1단계
# ──────────────────────────────────────────────


class TestBlockedRegex:
    """1단계 Regex 로 정형 PII 를 차단하는 시나리오."""

    async def test_phone_number_blocked(self, layer):
        # 전화번호 패턴 → 차단
        result = await layer.check(
            _req("연락처는 010-1234-5678 입니다"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "pii" in result.tags
        assert "PII detected" in result.reason

    async def test_resident_id_blocked(self, layer):
        # 주민등록번호 패턴 → 차단
        result = await layer.check(
            _req("주민번호 900101-1234567 입니다"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "PII detected" in result.reason

    async def test_email_blocked(self, layer):
        # 이메일 패턴 → 차단
        result = await layer.check(
            _req("메일은 user@gmail.com 입니다"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "PII detected" in result.reason

    async def test_openai_api_key_blocked(self, layer):
        # OpenAI API 키 패턴 → 차단
        result = await layer.check(
            _req("sk-abcdefghijklmnopqrstuvwxyz1234"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "PII detected" in result.reason

    async def test_aws_key_blocked(self, layer):
        # AWS 키 패턴 → 차단
        result = await layer.check(
            _req("AKIAIOSFODNN7EXAMPLE"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "PII detected" in result.reason

    async def test_bearer_token_blocked(self, layer):
        # Bearer 토큰 패턴 → 차단
        result = await layer.check(
            _req("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "PII detected" in result.reason

    async def test_extra_pattern_blocked(self, layer_with_extra):
        # 외부 주입 패턴 매칭 → 차단
        result = await layer_with_extra.check(
            _req("프로젝트 코드 PROJ-123456 입니다"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "PII detected" in result.reason

    async def test_blocked_reason_contains_position(self, layer):
        # reason 포맷: 'PII detected: {pii_type} at position {N}'
        result = await layer.check(
            _req("연락처는 010-1234-5678 입니다"),
        )
        assert result.allowed is False
        assert "at position" in result.reason


# ──────────────────────────────────────────────
# 3. 차단 골든 패스 — NER 2단계
# ──────────────────────────────────────────────


class TestBlockedNER:
    """2단계 NER 로 엔티티 조합을 차단하는 시나리오."""

    async def test_person_location_blocked(self, layer_with_ner, monkeypatch):
        # PERSON + LOCATION 조합 → 차단
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {"entity": "PERSON", "word": "홍길동", "start": 0},
                {
                    "entity": "LOCATION",
                    "word": "서울",
                    "start": 5,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "pii" in result.tags
        assert "ner" in result.tags
        assert "PII detected" in result.reason

    async def test_person_dob_blocked(self, layer_with_ner, monkeypatch):
        # PERSON + DATE_OF_BIRTH 조합 → 차단
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {"entity": "PERSON", "word": "김철수", "start": 0},
                {
                    "entity": "DATE_OF_BIRTH",
                    "word": "1990년 1월 1일",
                    "start": 8,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("김철수의 생일은 1990년 1월 1일이다"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "ner" in result.tags

    async def test_ner_blocked_reason_format(self, layer_with_ner, monkeypatch):
        # NER 차단 reason 포맷 검증
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {"entity": "PERSON", "word": "홍길동", "start": 0},
                {
                    "entity": "LOCATION",
                    "word": "서울",
                    "start": 5,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.allowed is False
        assert "PII detected:" in result.reason
        assert "at position" in result.reason


# ──────────────────────────────────────────────
# 4. 엣지 케이스
# ──────────────────────────────────────────────


class TestEdgeCases:
    """경계 조건과 특수 시나리오."""

    async def test_ner_model_not_loaded_allows(self, layer):
        # NER 모델 미로드 → fail-open (Regex 만 동작)
        # Regex 에 안 걸리는 NER 전용 입력 → 허용
        result = await layer.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.allowed is True

    async def test_ner_exception_allows(self, layer_with_ner, monkeypatch):
        # NER 추론 중 예외 발생 → fail-open → 허용
        def _boom(text):
            msg = "NER model inference failed"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            _boom,
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.allowed is True

    async def test_organization_only_allowed(self, layer_with_ner, monkeypatch):
        # ORGANIZATION 단독 → 오탐 방지 → 허용
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "ORGANIZATION",
                    "word": "삼성전자",
                    "start": 0,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("삼성전자 주가가 올랐다"),
        )
        assert result.allowed is True

    async def test_person_organization_allowed(
        self, layer_with_ner, monkeypatch
    ):
        # PERSON + ORGANIZATION → 차단 대상 아님 → 허용
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {"entity": "PERSON", "word": "이순신", "start": 0},
                {
                    "entity": "ORGANIZATION",
                    "word": "해군",
                    "start": 5,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("이순신이 해군에서 활동했다"),
        )
        assert result.allowed is True

    async def test_regex_blocks_before_ner(self, layer_with_ner, monkeypatch):
        # Regex 에서 먼저 차단 → NER 스킵
        # NER 은 호출되지 않아야 한다
        ner_called = {"value": False}

        def _ner_spy(text):
            ner_called["value"] = True
            return []

        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            _ner_spy,
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("전화번호 010-1234-5678"),
        )
        assert result.allowed is False
        # Regex 에서 차단했으므로 NER 은 호출되지 않아야 한다
        assert ner_called["value"] is False

    async def test_multiple_regex_first_match_reported(self, layer):
        # 여러 PII 가 있을 때 첫 번째 매칭을 보고
        result = await layer.check(
            _req("010-1234-5678 user@test.com"),
        )
        assert result.allowed is False
        assert "PII detected" in result.reason

    async def test_phone_number_landline_blocked(self, layer):
        # 유선전화 패턴도 매칭
        result = await layer.check(
            _req("사무실 02-123-4567"),
        )
        assert result.allowed is False

    async def test_ner_empty_entities_allowed(
        self, layer_with_ner, monkeypatch
    ):
        # NER 이 엔티티를 하나도 찾지 못하면 허용
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("일반적인 문장입니다"),
        )
        assert result.allowed is True


# ──────────────────────────────────────────────
# 5. LayerResult 형태 검증
# ──────────────────────────────────────────────


class TestLayerResultShape:
    """LayerResult 필드 규격 검증."""

    async def test_allowed_result_shape(self, layer):
        # 허용 시 전체 필드 규격 확인
        result = await layer.check(
            _req("정상적인 문장입니다"),
        )
        assert result.name == "L5"
        assert result.allowed is True
        assert result.reason is None
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
        assert result.tags == []
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_blocked_regex_result_shape(self, layer):
        # Regex 차단 시 전체 필드 규격 확인
        result = await layer.check(
            _req("연락처 010-1234-5678"),
        )
        assert result.name == "L5"
        assert result.allowed is False
        assert result.reason is not None
        assert isinstance(result.reason, str)
        assert result.severity == Severity.HIGH
        assert result.confidence == 0.0
        assert isinstance(result.tags, list)
        assert "pii" in result.tags
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_blocked_ner_result_shape(self, layer_with_ner, monkeypatch):
        # NER 차단 시 전체 필드 규격 확인
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {"entity": "PERSON", "word": "홍길동", "start": 0},
                {
                    "entity": "LOCATION",
                    "word": "서울",
                    "start": 5,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.name == "L5"
        assert result.allowed is False
        assert result.reason is not None
        assert isinstance(result.reason, str)
        assert result.severity == Severity.HIGH
        assert result.confidence == 0.0
        assert isinstance(result.tags, list)
        assert "pii" in result.tags
        assert "ner" in result.tags
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_empty_input_result_shape(self, layer):
        # 빈 입력 허용 시 규격 확인
        result = await layer.check(_req(""))
        assert result.name == "L5"
        assert result.allowed is True
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0

    async def test_fail_open_result_shape(self, layer):
        # fail-open 허용 시에도 규격 유지
        result = await layer.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.name == "L5"
        assert result.allowed is True
        assert result.severity == Severity.NONE
        assert result.confidence == 1.0
