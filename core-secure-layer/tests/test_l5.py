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
    min_score: float = 0.0,
    label_map: dict[str, str] | None = None,
    block_singletons: list[str] | None = None,
    aggregation_strategy: str = "simple",
) -> L5Layer:
    """__init__ 을 우회해 L5Layer 인스턴스를 만드는 테스트용 팩토리.

    pii_labels.json / HF 파이프라인 로드 없이도 `_check_regex` /
    `_check_ner` 를 그대로 실행할 수 있도록 필수 속성을 모두 세팅한다.
    테스트 별로 `min_score`/`label_map`/`block_singletons` 을 주입해
    차단 계약을 시나리오 별로 재구성할 수 있다.
    """
    inst = L5Layer.__new__(L5Layer)
    inst.name = "L5"
    inst.model_name = "ner-ko"
    inst.extra_patterns = list(extra_patterns or [])
    inst.min_score = min_score
    inst.label_map = dict(label_map or {})
    inst.block_singletons = frozenset(block_singletons or [])
    inst.aggregation_strategy = aggregation_strategy
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


def _layer_blocking_person() -> L5Layer:
    """PERSON 을 singleton 차단 목록에 포함한 L5Layer.

    NER 차단 경로를 시뮬레이션하는 테스트들의 공통 팩토리.
    `label_map` 은 비워 두고 raw 라벨(예: "PERSON") 이 그대로 singleton
    집합과 비교되도록 한다. `min_score=0.5`, 엔티티는 `score>=0.9` 로
    주면 컷오프를 통과한다.
    """
    return _new_layer(
        ner_model=MagicMock(),
        min_score=0.5,
        block_singletons=["PERSON"],
    )


class TestBlockedNER:
    """2단계 NER 이 `block_singletons` 기반으로 차단하는 시나리오."""

    async def test_person_singleton_blocked(self, monkeypatch):
        # PERSON 이 singleton 집합에 있으면 충분한 score 일 때 차단.
        layer_ = _layer_blocking_person()
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PERSON",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.95,
                },
                {
                    "entity": "LOCATION",
                    "word": "서울",
                    "start": 5,
                    "score": 0.90,
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("홍길동이 서울에 산다"))
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "pii" in result.tags
        assert "ner" in result.tags
        assert "PII detected" in result.reason

    async def test_label_map_normalizes_singleton(self, monkeypatch):
        # raw 라벨이 label_map 을 통해 singleton 타입으로 정규화된다.
        layer_ = _new_layer(
            ner_model=MagicMock(),
            min_score=0.5,
            label_map={"이름": "person"},
            block_singletons=["person"],
        )
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "B-이름",
                    "word": "김철수",
                    "start": 0,
                    "score": 0.88,
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("김철수 생일은 ..."))
        assert result.allowed is False
        assert "person" in result.tags  # 정규화된 타입이 태그에 포함

    async def test_ner_blocked_reason_format(self, monkeypatch):
        # NER 차단 reason 포맷 검증 — `PII detected: {pii_type} at ...`.
        layer_ = _layer_blocking_person()
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PERSON",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.95,
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("홍길동이 서울에 산다"))
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

    async def test_blocked_ner_result_shape(self, monkeypatch):
        # NER singleton 차단 시 전체 필드 규격 확인
        layer_ = _layer_blocking_person()
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PERSON",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.95,
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("홍길동이 서울에 산다"))
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


# ──────────────────────────────────────────────
# 6. score 필터 / block_singletons 게이트 (신규 계약)
# ──────────────────────────────────────────────


class TestScoreFilter:
    """`min_score` 아래의 엔티티는 무시되어야 한다."""

    async def test_entity_below_min_score_allowed(self, monkeypatch):
        layer_ = _new_layer(
            ner_model=MagicMock(),
            min_score=0.7,
            block_singletons=["PERSON"],
        )
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PERSON",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.5,  # < min_score
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("홍길동 어쩌구"))
        assert result.allowed is True

    async def test_first_qualifying_entity_used(self, monkeypatch):
        # 앞의 엔티티가 컷오프 미달이면 스킵하고 뒤의 적합 엔티티 사용.
        layer_ = _new_layer(
            ner_model=MagicMock(),
            min_score=0.7,
            block_singletons=["PERSON"],
        )
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PERSON",
                    "word": "a",
                    "start": 0,
                    "score": 0.3,  # 컷오프 미달
                },
                {
                    "entity": "PERSON",
                    "word": "홍길동",
                    "start": 10,
                    "score": 0.95,  # 컷오프 통과
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("..."))
        assert result.allowed is False
        assert "at position 10" in result.reason


class TestBlockSingletonsGate:
    """정규화된 타입이 singleton 에 없으면 통과."""

    async def test_entity_not_in_singletons_allowed(self, monkeypatch):
        layer_ = _new_layer(
            ner_model=MagicMock(),
            min_score=0.5,
            block_singletons=["person"],  # 이 집합에 없는 타입은 허용
        )
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "DATE",
                    "word": "2025-01-01",
                    "start": 0,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("2025-01-01"))
        assert result.allowed is True


# ──────────────────────────────────────────────
# 7. ADMIN 정책 주입 — 생성자 오버라이드 / 라이브 갱신
# ──────────────────────────────────────────────


class TestAdminPolicyInjection:
    """정책 주입 표면(생성자 kwarg + 평평한 속성 갱신) 검증.

    차후 ADMIN 백엔드가 정책 데이터를 주입할 때 동작으로 이어지는지
    확인한다. 두 경로 모두 _check_ner 에 영향을 줘야 한다.
    """

    async def test_constructor_override_changes_behavior(self, monkeypatch):
        # 생성자 min_score=0.95 로 인스턴스 → 파일값(또는 기본값) 무시.
        # score 0.9 엔티티는 컷오프 미달 → 허용.
        layer_ = _new_layer(
            ner_model=MagicMock(),
            min_score=0.95,
            block_singletons=["PERSON"],
        )
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PERSON",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.9,
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("홍길동"))
        assert result.allowed is True

    async def test_live_attribute_update_applies_next_call(self, monkeypatch):
        # 기존 인스턴스의 min_score 를 대입만으로 상향 → 다음 요청부터
        # 같은 입력이 새 임계값을 참조해 허용으로 바뀐다.
        layer_ = _new_layer(
            ner_model=MagicMock(),
            min_score=0.5,
            block_singletons=["PERSON"],
        )
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PERSON",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.7,
                },
            ],
            raising=False,
        )
        first = await layer_.check(_req("홍길동"))
        assert first.allowed is False  # 0.7 >= 0.5 → 차단

        # ADMIN 정책 핫스왑을 흉내: 속성 대입만으로 임계값 갱신.
        layer_.min_score = 0.9
        second = await layer_.check(_req("홍길동"))
        assert second.allowed is True  # 0.7 < 0.9 → 허용

    async def test_constructor_override_labels_and_singletons(
        self, monkeypatch
    ):
        # ADMIN 이 모델 폴더와 다른 label_map / block_singletons 를 주입해도
        # 생성자 인자로 오버라이드되어 차단 로직에 즉시 반영.
        layer_ = _new_layer(
            ner_model=MagicMock(),
            min_score=0.5,
            label_map={"SSN": "resident_id"},
            block_singletons=["resident_id"],
        )
        monkeypatch.setattr(
            layer_,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "B-SSN",
                    "word": "XXX",
                    "start": 0,
                    "score": 0.9,
                },
            ],
            raising=False,
        )
        result = await layer_.check(_req("일부러 SSN"))
        assert result.allowed is False
        assert "resident_id" in result.tags


# ──────────────────────────────────────────────
# 8. pii_labels.json 로더 — 동작 기본값 검증
# ──────────────────────────────────────────────


class TestPiiLabelsLoader:
    """파일 로드 결과가 L5Layer 속성으로 정상 전이되는지."""

    def test_loads_values_from_pii_labels_json(self, tmp_path):
        # 임시 모델 폴더에 pii_labels.json 을 심고 _load_pii_labels 호출.
        import json as _json

        from core_secure_layer.layers.l5 import l5 as l5_mod

        model_dir = tmp_path / "fake_model"
        model_dir.mkdir()
        (model_dir / "pii_labels.json").write_text(
            _json.dumps(
                {
                    "label_map": {"PS": "person"},
                    "block_singletons": ["person"],
                    "block_combinations": [],
                    "min_score": 0.77,
                    "aggregation_strategy": "simple",
                }
            ),
            encoding="utf-8",
        )
        cfg = l5_mod._load_pii_labels(model_dir)
        assert cfg["min_score"] == 0.77
        assert cfg["label_map"] == {"PS": "person"}
        assert cfg["block_singletons"] == ["person"]
        assert cfg["aggregation_strategy"] == "simple"

    def test_missing_pii_labels_file_yields_defaults(self, tmp_path):
        from core_secure_layer.layers.l5 import l5 as l5_mod

        missing = tmp_path / "no_model"
        missing.mkdir()
        cfg = l5_mod._load_pii_labels(missing)
        assert cfg["min_score"] == 0.0  # fail-open, 필터 미적용
        assert cfg["label_map"] == {}
        assert cfg["block_singletons"] == []
        assert cfg["aggregation_strategy"] == "simple"
