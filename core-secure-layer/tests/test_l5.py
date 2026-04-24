import json
from unittest.mock import MagicMock

import pytest

from core_secure_layer.layers.l5 import l5 as l5_mod
from core_secure_layer.layers.l5.l5 import L5Layer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    Severity,
)


def _req(text):
    """주어진 텍스트로 GuardrailRequest 를 생성한다."""
    return GuardrailRequest(user_input=text)


def _attach_pii_spec(
    inst,
    *,
    label_map=None,
    block_singletons=None,
    block_combinations=None,
    min_score=0.0,
    aggregation_strategy="simple",
):
    """테스트용 L5Layer 인스턴스에 pii_labels 스펙을 주입한다.

    리팩터링 이후 L5Layer 는 모델 폴더의 pii_labels.json 을
    읽어 아래 속성들을 채우는 설계다. 테스트에서는 모델 로드를
    우회하기 위해 동일 속성을 직접 주입한다.
    """
    inst._label_map = label_map if label_map is not None else {}
    inst._block_singletons = (
        block_singletons if block_singletons is not None else []
    )
    inst._block_combinations = (
        block_combinations if block_combinations is not None else []
    )
    inst._min_score = min_score
    inst._aggregation_strategy = aggregation_strategy


@pytest.fixture
def layer():
    """NER 모델 미로드 상태의 L5Layer 인스턴스.

    Regex 1단계만 동작하고, NER 2단계는 fail-open 으로 허용.
    """
    inst = L5Layer.__new__(L5Layer)
    inst.name = "L5"
    inst.extra_patterns = []
    inst._ner_model = None
    _attach_pii_spec(inst)
    return inst


@pytest.fixture
def layer_with_extra():
    """extra_patterns 가 설정된 L5Layer 인스턴스.

    외부 주입 정규식 매칭 테스트용.
    """
    inst = L5Layer.__new__(L5Layer)
    inst.name = "L5"
    inst.extra_patterns = [r"PROJ-\d{6}"]
    inst._ner_model = None
    _attach_pii_spec(inst)
    return inst


@pytest.fixture
def layer_with_ner():
    """PII 특화 모델 스펙이 주입된 L5Layer 인스턴스.

    label_map 은 원본 라벨을 정규화된 PII 타입으로 매핑하고,
    모든 타입을 block_singletons 에 넣어 "감지 즉시 차단"
    동작을 표현한다. ner-ko 와 동일한 의미.
    """
    inst = L5Layer.__new__(L5Layer)
    inst.name = "L5"
    inst.extra_patterns = []
    inst._ner_model = MagicMock()
    _attach_pii_spec(
        inst,
        label_map={
            "이름": "person",
            "전화번호": "phone_number",
            "전자메일": "email",
            "상세주소": "address",
            "PERSON": "person",
            "LOCATION": "location",
            "DATE_OF_BIRTH": "date_of_birth",
        },
        block_singletons=[
            "person",
            "phone_number",
            "email",
            "address",
            "date_of_birth",
        ],
        block_combinations=[],
        min_score=0.0,
        aggregation_strategy="simple",
    )
    return inst


@pytest.fixture
def layer_generic_ner():
    """범용 NER 모델 스펙이 주입된 L5Layer 인스턴스.

    person 단독은 허용하고, [person, location] 조합만 차단한다.
    pii_labels.json 이 조합 차단을 정의한 경우를 표현한다.
    """
    inst = L5Layer.__new__(L5Layer)
    inst.name = "L5"
    inst.extra_patterns = []
    inst._ner_model = MagicMock()
    _attach_pii_spec(
        inst,
        label_map={
            "PS": "person",
            "LC": "location",
            "DT": "date",
            "OG": "organization",
            "PERSON": "person",
            "LOCATION": "location",
        },
        block_singletons=[],
        block_combinations=[["person", "location"]],
        min_score=0.85,
        aggregation_strategy="simple",
    )
    return inst


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
# 1. pii_labels.json 로딩 / 폴백 / fail-open
# ──────────────────────────────────────────────


class TestPIILabelsLoading:
    """모델 폴더의 pii_labels.json 을 읽어 판정 규칙을 구성한다."""

    def test_json_populates_spec_attributes(self, tmp_path, monkeypatch):
        # pii_labels.json 이 존재하면 그 값이 인스턴스 속성에 반영된다
        model_dir = tmp_path / "custom-ner"
        model_dir.mkdir()
        (model_dir / "config.json").write_text(
            json.dumps({"id2label": {"0": "O"}}),
            encoding="utf-8",
        )
        spec = {
            "label_map": {"PS": "person", "LC": "location"},
            "block_singletons": ["person"],
            "block_combinations": [["person", "location"]],
            "min_score": 0.77,
            "aggregation_strategy": "first",
        }
        (model_dir / "pii_labels.json").write_text(
            json.dumps(spec, ensure_ascii=False),
            encoding="utf-8",
        )

        # 모델 베이스 경로를 tmp_path 로 치환
        monkeypatch.setattr(
            l5_mod,
            "_MODEL_BASE_DIR",
            tmp_path,
        )
        # transformers.pipeline 은 호출만 확인 — 실제 로드 방지
        monkeypatch.setattr(
            l5_mod,
            "pipeline",
            lambda *args, **kwargs: MagicMock(),
        )

        inst = L5Layer(model_name="custom-ner")

        assert inst._label_map == {
            "PS": "person",
            "LC": "location",
        }
        assert inst._block_singletons == ["person"]
        assert inst._block_combinations == [["person", "location"]]
        assert inst._min_score == 0.77
        assert inst._aggregation_strategy == "first"

    def test_missing_json_falls_back_to_id2label(
        self, tmp_path, monkeypatch, caplog
    ):
        # pii_labels.json 이 없으면 config.json 의 id2label 로
        # label_map 을 자동 생성하고 전 라벨을 block_singletons 에
        # 넣는 관대 폴백으로 동작하며 경고 로그가 1회 발생한다
        model_dir = tmp_path / "fallback-ner"
        model_dir.mkdir()
        (model_dir / "config.json").write_text(
            json.dumps(
                {
                    "id2label": {
                        "0": "O",
                        "1": "B-PS",
                        "2": "I-PS",
                        "3": "B-LC",
                        "4": "I-LC",
                    }
                }
            ),
            encoding="utf-8",
        )

        monkeypatch.setattr(
            l5_mod,
            "_MODEL_BASE_DIR",
            tmp_path,
        )
        monkeypatch.setattr(
            l5_mod,
            "pipeline",
            lambda *args, **kwargs: MagicMock(),
        )

        with caplog.at_level("WARNING"):
            inst = L5Layer(model_name="fallback-ner")

        # B-/I- 접두사 제거된 라벨만 남는다
        assert "PS" in inst._label_map
        assert "LC" in inst._label_map
        # 폴백은 라벨 원본을 정규화 타입으로 그대로 사용
        assert inst._label_map["PS"] == "PS"
        assert inst._label_map["LC"] == "LC"
        # 모든 라벨이 singleton 차단에 포함되어야 한다
        assert set(inst._block_singletons) == {"PS", "LC"}
        assert inst._block_combinations == []
        assert inst._min_score == 0.0
        assert inst._aggregation_strategy == "simple"
        # 경고 로그 1회 발생
        warning_records = [
            r for r in caplog.records if r.levelname == "WARNING"
        ]
        assert len(warning_records) >= 1
        assert any("pii_labels.json" in r.getMessage() for r in warning_records)

    def test_invalid_json_disables_ner(self, tmp_path, monkeypatch):
        # JSON 파싱 실패 시 NER 은 비활성화 (fail-open)
        model_dir = tmp_path / "broken-ner"
        model_dir.mkdir()
        (model_dir / "config.json").write_text(
            json.dumps({"id2label": {"0": "O"}}),
            encoding="utf-8",
        )
        # 잘못된 JSON
        (model_dir / "pii_labels.json").write_text(
            "{ this is not valid json",
            encoding="utf-8",
        )

        monkeypatch.setattr(
            l5_mod,
            "_MODEL_BASE_DIR",
            tmp_path,
        )
        monkeypatch.setattr(
            l5_mod,
            "pipeline",
            lambda *args, **kwargs: MagicMock(),
        )

        inst = L5Layer(model_name="broken-ner")

        # NER 비활성화
        assert inst._ner_model is None

    def test_aggregation_strategy_passed_to_pipeline(
        self, tmp_path, monkeypatch
    ):
        # pii_labels.json 의 aggregation_strategy 값이
        # transformers.pipeline 호출에 그대로 전달된다
        model_dir = tmp_path / "agg-ner"
        model_dir.mkdir()
        (model_dir / "config.json").write_text(
            json.dumps({"id2label": {"0": "O"}}),
            encoding="utf-8",
        )
        (model_dir / "pii_labels.json").write_text(
            json.dumps(
                {
                    "label_map": {"PS": "person"},
                    "block_singletons": ["person"],
                    "block_combinations": [],
                    "min_score": 0.0,
                    "aggregation_strategy": "max",
                }
            ),
            encoding="utf-8",
        )

        monkeypatch.setattr(
            l5_mod,
            "_MODEL_BASE_DIR",
            tmp_path,
        )

        captured = {}

        def _fake_pipeline(*args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return MagicMock()

        monkeypatch.setattr(l5_mod, "pipeline", _fake_pipeline)

        L5Layer(model_name="agg-ner")

        assert captured["kwargs"].get("aggregation_strategy") == "max"


# ──────────────────────────────────────────────
# 2. 허용 골든 패스
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

    async def test_person_only_allowed_when_not_singleton(
        self, layer_generic_ner, monkeypatch
    ):
        # 범용 모델: person 은 singleton 아님 → 단독 감지 시 허용
        monkeypatch.setattr(
            layer_generic_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PS",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_generic_ner.check(
            _req("홍길동이 좋아한다"),
        )
        assert result.allowed is True
        assert result.reason is None

    async def test_empty_string_allowed(self, layer):
        # 빈 문자열 → 탐지 대상 없음 → 허용
        result = await layer.check(_req(""))
        assert result.allowed is True


# ──────────────────────────────────────────────
# 3. 차단 골든 패스 — Regex 1단계
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
# 4. 차단 골든 패스 — NER 2단계 (singleton / combination)
# ──────────────────────────────────────────────


class TestBlockedNERSingleton:
    """block_singletons 로 단일 감지 차단."""

    async def test_person_singleton_blocked(self, layer_with_ner, monkeypatch):
        # person 이 singleton 차단 대상 → 감지 시 차단
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "B-이름",
                    "word": "홍길동",
                    "start": 3,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("사용자 홍길동 님"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "pii" in result.tags
        assert "ner" in result.tags
        assert "person" in result.tags
        assert "PII detected: person at position 3" in result.reason

    async def test_phone_singleton_blocked_tags(
        self, layer_with_ner, monkeypatch
    ):
        # phone_number singleton 차단 시 tags 에 타입 포함
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "전화번호",
                    "word": "010-0000-0000",
                    "start": 0,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(_req("전화 번호 감지 테스트"))
        assert result.allowed is False
        assert "phone_number" in result.tags

    async def test_bi_prefix_normalized(self, layer_with_ner, monkeypatch):
        # B-이름 / I-이름 접두사가 정규화되어 label_map 조회 성공
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "I-이름",
                    "word": "길동",
                    "start": 2,
                    "score": 0.95,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(_req("홍 길동 입니다"))
        assert result.allowed is False
        assert "person" in result.tags


class TestBlockedNERCombination:
    """block_combinations 로 조합 감지 차단."""

    async def test_person_alone_not_blocked(
        self, layer_generic_ner, monkeypatch
    ):
        # 조합 [person, location] 중 person 만 감지 → 허용
        monkeypatch.setattr(
            layer_generic_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PS",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_generic_ner.check(
            _req("홍길동이 좋아한다"),
        )
        assert result.allowed is True

    async def test_person_location_blocked(
        self, layer_generic_ner, monkeypatch
    ):
        # person + location 둘 다 감지 → 조합 매칭 → 차단
        monkeypatch.setattr(
            layer_generic_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PS",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.99,
                },
                {
                    "entity": "LC",
                    "word": "서울",
                    "start": 5,
                    "score": 0.98,
                },
            ],
            raising=False,
        )
        result = await layer_generic_ner.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert "pii" in result.tags
        assert "ner" in result.tags
        assert "person" in result.tags
        assert "location" in result.tags
        # combination reason 포맷: "PII detected: t1+t2+..."
        assert "PII detected:" in result.reason
        assert "person" in result.reason
        assert "location" in result.reason
        assert "+" in result.reason

    async def test_combination_partial_match_allowed(
        self, layer_generic_ner, monkeypatch
    ):
        # 조합에 포함되지 않은 라벨(date, organization) 만 감지 → 허용
        monkeypatch.setattr(
            layer_generic_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "DT",
                    "word": "2024년",
                    "start": 0,
                    "score": 0.99,
                },
                {
                    "entity": "OG",
                    "word": "삼성전자",
                    "start": 10,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_generic_ner.check(
            _req("2024년 삼성전자 실적"),
        )
        assert result.allowed is True


class TestNERAlgorithmDetails:
    """NER 판정 알고리즘 세부: singleton 우선, min_score, label_map 필터."""

    async def test_singleton_checked_before_combination(
        self, layer_with_ner, monkeypatch
    ):
        # singleton 과 combination 이 둘 다 정의된 경우 singleton 우선
        # layer_with_ner 는 person 이 singleton → 단독으로도 차단
        layer_with_ner._block_combinations = [
            ["person", "location"],
        ]
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "이름",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("홍길동"),
        )
        assert result.allowed is False
        # singleton 포맷: "... at position N"
        assert "at position" in result.reason

    async def test_min_score_filters_low_confidence(
        self, layer_generic_ner, monkeypatch
    ):
        # min_score=0.85 설정, 조합 [person, location]
        # 두 엔티티가 감지돼도 모두 min_score 미만이면 무시 → 허용
        monkeypatch.setattr(
            layer_generic_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PS",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.5,
                },
                {
                    "entity": "LC",
                    "word": "서울",
                    "start": 5,
                    "score": 0.4,
                },
            ],
            raising=False,
        )
        result = await layer_generic_ner.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.allowed is True

    async def test_label_not_in_map_ignored(self, layer_with_ner, monkeypatch):
        # label_map 에 없는 라벨 → 무시 → 허용
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "MISC",
                    "word": "무엇인가",
                    "start": 0,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("무엇인가 있다"),
        )
        assert result.allowed is True

    async def test_no_matching_type_allowed(self, layer_with_ner, monkeypatch):
        # label_map 에는 있지만 singleton / combination 어디에도
        # 해당하지 않는 타입 → 허용
        # layer_with_ner 의 block_singletons 에 location 이 없도록 수정
        layer_with_ner._block_singletons = ["phone_number"]
        layer_with_ner._block_combinations = []
        layer_with_ner._label_map["LOCATION"] = "location"
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "LOCATION",
                    "word": "서울",
                    "start": 0,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(_req("서울에 간다"))
        assert result.allowed is True


# ──────────────────────────────────────────────
# 5. 엣지 케이스
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
# 6. LayerResult 형태 검증
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

    async def test_blocked_ner_singleton_result_shape(
        self, layer_with_ner, monkeypatch
    ):
        # NER singleton 차단 시 전체 필드 규격 확인
        monkeypatch.setattr(
            layer_with_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "이름",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_with_ner.check(
            _req("홍길동 님"),
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
        assert "person" in result.tags
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    async def test_blocked_ner_combination_result_shape(
        self, layer_generic_ner, monkeypatch
    ):
        # NER combination 차단 시 tags 에 모든 타입 포함,
        # reason 은 "t1+t2+..." 포맷
        monkeypatch.setattr(
            layer_generic_ner,
            "_ner_predict",
            lambda text: [
                {
                    "entity": "PS",
                    "word": "홍길동",
                    "start": 0,
                    "score": 0.99,
                },
                {
                    "entity": "LC",
                    "word": "서울",
                    "start": 5,
                    "score": 0.99,
                },
            ],
            raising=False,
        )
        result = await layer_generic_ner.check(
            _req("홍길동이 서울에 산다"),
        )
        assert result.name == "L5"
        assert result.allowed is False
        assert result.severity == Severity.HIGH
        assert result.confidence == 0.0
        assert "pii" in result.tags
        assert "ner" in result.tags
        assert "person" in result.tags
        assert "location" in result.tags
        assert "+" in result.reason

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
# 7. ner-ko 전용 회귀 방지
# ──────────────────────────────────────────────


class TestNerKoRegression:
    """실제 ner-ko 모델 폴더의 pii_labels.json 이 제대로 로드되는지."""

    def test_ner_ko_spec_loaded(self, monkeypatch):
        # 실제 ner-ko 모델 폴더를 사용하되 pipeline 은 mock
        monkeypatch.setattr(
            l5_mod,
            "pipeline",
            lambda *args, **kwargs: MagicMock(),
        )

        inst = L5Layer(model_name="ner-ko")

        # label_map 정규화 타입 샘플 확인
        assert inst._label_map.get("이름") == "person"
        assert inst._label_map.get("전화번호") == "phone_number"
        assert inst._label_map.get("주민등록번호") == "resident_id"

        # block_singletons 에 15개 타입 모두 포함
        expected_singletons = {
            "person",
            "phone_number",
            "mobile_number",
            "resident_id",
            "account_number",
            "card_number",
            "passport_number",
            "driver_license",
            "email",
            "login_id",
            "address",
            "zip_code",
            "merchant",
            "payment_amount",
            "credit_score",
        }
        assert expected_singletons.issubset(set(inst._block_singletons))
        assert inst._block_combinations == []
