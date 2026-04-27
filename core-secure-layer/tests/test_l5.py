import contextlib
import itertools
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

    @pytest.fixture(autouse=True)
    def _skip_real_model_load(self, monkeypatch):
        # 생성자 계약 테스트는 실제 ner-ko 모델 로딩이 불필요하므로 스킵.
        # PIILabelsLoading / NerKoRegression 은 자체 monkeypatch 로 pipeline
        # 만 가짜로 치환하므로 이 픽스처의 영향권 밖이다.
        monkeypatch.setattr(
            L5Layer,
            "_load_ner_model",
            lambda self, name: None,
        )

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


class TestMinScoreOverride:
    """생성자의 min_score 파라미터가 JSON 스펙을 override 한다."""

    def _make_model(self, tmp_path, spec_min_score):
        # 공통 준비: pii_labels.json 에 주어진 min_score 를 담은 모델 폴더
        model_dir = tmp_path / "override-ner"
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
                    "min_score": spec_min_score,
                    "aggregation_strategy": "simple",
                }
            ),
            encoding="utf-8",
        )
        return model_dir

    def test_constructor_min_score_overrides_json(self, tmp_path, monkeypatch):
        # JSON 에 0.5 가 있어도 생성자가 0.99 를 주면 0.99 가 쓰인다
        self._make_model(tmp_path, spec_min_score=0.5)
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        monkeypatch.setattr(
            l5_mod,
            "pipeline",
            lambda *args, **kwargs: MagicMock(),
        )

        inst = L5Layer(model_name="override-ner", min_score=0.99)

        assert inst._min_score == 0.99

    def test_min_score_from_json_when_not_overridden(
        self, tmp_path, monkeypatch
    ):
        # 생성자에서 min_score 를 안 주면 JSON 값(0.5) 이 그대로 쓰인다
        self._make_model(tmp_path, spec_min_score=0.5)
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        monkeypatch.setattr(
            l5_mod,
            "pipeline",
            lambda *args, **kwargs: MagicMock(),
        )

        inst = L5Layer(model_name="override-ner")

        assert inst._min_score == 0.5

    def test_constructor_min_score_overrides_fallback(
        self, tmp_path, monkeypatch
    ):
        # pii_labels.json 이 없어 폴백 경로여도 생성자 값이 적용된다
        model_dir = tmp_path / "no-json-ner"
        model_dir.mkdir()
        (model_dir / "config.json").write_text(
            json.dumps(
                {"id2label": {"0": "O", "1": "B-PS", "2": "I-PS"}},
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        monkeypatch.setattr(
            l5_mod,
            "pipeline",
            lambda *args, **kwargs: MagicMock(),
        )

        inst = L5Layer(model_name="no-json-ner", min_score=0.75)

        assert inst._min_score == 0.75


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
        # "오탐 절대 불허" 원칙 핵심 값 — 회귀 방지로 임계값 고정
        assert inst._min_score == pytest.approx(0.7)


# ──────────────────────────────────────────────
# 8. Char-level HF 어댑터 — dispatch / 로딩 / 추론
# ──────────────────────────────────────────────


def _write_charlevel_model_dir(
    tmp_path,
    name="charlevel-ner",
    *,
    adapter="hf-charlevel",
    label_map=None,
    block_singletons=None,
    block_combinations=None,
    min_score=0.7,
    max_length=256,
    include_id2label=True,
):
    """charlevel 어댑터용 모델 폴더와 pii_labels.json 생성."""
    model_dir = tmp_path / name
    model_dir.mkdir()
    if include_id2label:
        (model_dir / "config.json").write_text(
            json.dumps(
                {
                    "id2label": {
                        "0": "O",
                        "1": "B-PS",
                        "2": "I-PS",
                        "3": "B-PHONE",
                        "4": "I-PHONE",
                    }
                }
            ),
            encoding="utf-8",
        )
    spec = {
        "label_map": (
            label_map
            if label_map is not None
            else {"PS": "person", "PHONE": "phone_number"}
        ),
        "block_singletons": (
            block_singletons
            if block_singletons is not None
            else ["person", "phone_number"]
        ),
        "block_combinations": (
            block_combinations if block_combinations is not None else []
        ),
        "min_score": min_score,
        "max_length": max_length,
    }
    if adapter is not None:
        spec["adapter"] = adapter
    (model_dir / "pii_labels.json").write_text(
        json.dumps(spec, ensure_ascii=False),
        encoding="utf-8",
    )
    return model_dir


def _patch_pipeline(monkeypatch):
    """transformers.pipeline 을 MagicMock 으로 치환하는 헬퍼."""
    monkeypatch.setattr(
        l5_mod,
        "pipeline",
        lambda *args, **kwargs: MagicMock(),
    )


class TestAdapterDispatch:
    """pii_labels.json 의 adapter 필드에 따른 어댑터 분기."""

    def test_explicit_hf_pipeline_uses_pipeline_adapter(
        self, tmp_path, monkeypatch
    ):
        # adapter="hf-pipeline" 명시 → _HFPipelineAdapter 인스턴스
        _write_charlevel_model_dir(
            tmp_path,
            name="explicit-pipeline",
            adapter="hf-pipeline",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)

        inst = L5Layer(model_name="explicit-pipeline")

        assert inst._adapter is not None
        assert isinstance(inst._adapter, l5_mod._HFPipelineAdapter)

    def test_default_adapter_is_hf_pipeline(self, tmp_path, monkeypatch):
        # adapter 필드가 생략되면 기본값 "hf-pipeline" 으로 동작 (회귀 방지)
        _write_charlevel_model_dir(
            tmp_path,
            name="no-adapter-field",
            adapter=None,
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)

        inst = L5Layer(model_name="no-adapter-field")

        assert inst._adapter is not None
        assert isinstance(inst._adapter, l5_mod._HFPipelineAdapter)

    def test_hf_charlevel_uses_charlevel_adapter(self, tmp_path, monkeypatch):
        # adapter="hf-charlevel" → _HFCharLevelAdapter 인스턴스
        _write_charlevel_model_dir(tmp_path, name="charlevel-ner")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        # charlevel 경로는 pipeline 을 쓰면 안 되지만, 안전하게 패치
        _patch_pipeline(monkeypatch)
        # AutoTokenizer/AutoModel monkeypatch
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(
                from_pretrained=MagicMock(return_value=fake_tokenizer),
            ),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(
                from_pretrained=MagicMock(return_value=fake_model),
            ),
            raising=False,
        )

        inst = L5Layer(model_name="charlevel-ner")

        assert inst._adapter is not None
        assert isinstance(inst._adapter, l5_mod._HFCharLevelAdapter)

    def test_unknown_adapter_disables_ner(self, tmp_path, monkeypatch):
        # 알 수 없는 adapter 값 → fail-open (어댑터/모델 모두 None)
        _write_charlevel_model_dir(
            tmp_path,
            name="unknown-adapter",
            adapter="totally-unknown-adapter",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)

        inst = L5Layer(model_name="unknown-adapter")

        assert inst._adapter is None
        assert inst._ner_model is None


class TestHFCharLevelAdapterLoading:
    """_HFCharLevelAdapter 생성자: 토크나이저/모델 로드 + [SP] 등록."""

    def _make_fakes(self, monkeypatch):
        # 가짜 토크나이저/모델을 만들고 from_pretrained 패치
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()

        tokenizer_cls = MagicMock(
            from_pretrained=MagicMock(return_value=fake_tokenizer),
        )
        model_cls = MagicMock(
            from_pretrained=MagicMock(return_value=fake_model),
        )
        monkeypatch.setattr(
            l5_mod, "AutoTokenizer", tokenizer_cls, raising=False
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            model_cls,
            raising=False,
        )
        return fake_tokenizer, fake_model, tokenizer_cls, model_cls

    def test_loads_tokenizer_and_adds_sp_token(self, tmp_path, monkeypatch):
        # AutoTokenizer.from_pretrained 호출 + [SP] 토큰 add_tokens 호출
        model_dir = _write_charlevel_model_dir(tmp_path)
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_tokenizer, _, tokenizer_cls, _ = self._make_fakes(monkeypatch)

        L5Layer(model_name=model_dir.name)

        # 토크나이저 from_pretrained 가 모델 폴더 경로로 호출됨
        called_paths = [
            str(c.args[0]) for c in tokenizer_cls.from_pretrained.call_args_list
        ]
        assert any(str(model_dir) in p for p in called_paths)
        # [SP] 토큰을 vocab 에 추가
        add_calls = fake_tokenizer.add_tokens.call_args_list
        assert len(add_calls) >= 1
        passed = add_calls[0].args[0]
        # ["[SP]"] 또는 "[SP]" 형태 모두 허용
        if isinstance(passed, list):
            assert "[SP]" in passed
        else:
            assert passed == "[SP]"

    def test_loads_model_and_resizes_embeddings(self, tmp_path, monkeypatch):
        # AutoModelForTokenClassification.from_pretrained 호출 +
        # resize_token_embeddings 호출 검증
        model_dir = _write_charlevel_model_dir(tmp_path)
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        _, fake_model, _, model_cls = self._make_fakes(monkeypatch)

        L5Layer(model_name=model_dir.name)

        called_paths = [
            str(c.args[0]) for c in model_cls.from_pretrained.call_args_list
        ]
        assert any(str(model_dir) in p for p in called_paths)
        # 토크나이저 vocab 확장에 맞춰 임베딩도 확장
        assert fake_model.resize_token_embeddings.called

    def test_model_set_to_eval_mode(self, tmp_path, monkeypatch):
        # 추론 전용으로 model.eval() 호출
        model_dir = _write_charlevel_model_dir(tmp_path)
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        _, fake_model, _, _ = self._make_fakes(monkeypatch)

        L5Layer(model_name=model_dir.name)

        assert fake_model.eval.called

    def test_load_failure_is_fail_open(self, tmp_path, monkeypatch):
        # 토크나이저 로드 중 예외 → fail-open (_adapter=None, _ner_model=None)
        _write_charlevel_model_dir(tmp_path, name="boom")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)

        def _raise(*_args, **_kwargs):
            msg = "tokenizer load failed"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(side_effect=_raise)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock()),
            raising=False,
        )

        inst = L5Layer(model_name="boom")

        assert inst._adapter is None
        assert inst._ner_model is None


class TestHFCharLevelInference:
    """_HFCharLevelAdapter.predict 의 입력 변환과 추론 흐름."""

    def _prepare(self, tmp_path, monkeypatch):
        # 어댑터 생성에 필요한 공통 fixture
        _write_charlevel_model_dir(tmp_path, name="charlevel-ner")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(return_value=fake_tokenizer)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock(return_value=fake_model)),
            raising=False,
        )
        return fake_tokenizer, fake_model

    def test_text_split_into_chars_with_sp_for_spaces(
        self, tmp_path, monkeypatch
    ):
        # "홍 길" → ["홍", "[SP]", "길"] 로 변환되어 토크나이저에 전달
        self._prepare(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        # _predict_chunk 가 외부 모델 호출을 우회하도록 패치
        # 어댑터는 _predict_chunk(chars) -> list[(label, score)] 형태를 가정
        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            lambda chars: [("O", 1.0)] * len(chars),
            raising=False,
        )

        inst._adapter.predict("홍 길")

        # 핵심 계약: "공백 → [SP] 토큰 치환" 을 어댑터가 수행해야 한다.
        # 어댑터가 변환을 외부에 노출하지 않으면 이 테스트는 실패한다.
        chars = inst._adapter._text_to_chars("홍 길")
        assert chars == ["홍", "[SP]", "길"]

    def test_tokenizer_called_with_is_split_into_words(
        self, tmp_path, monkeypatch
    ):
        # 토크나이저 호출 시 is_split_into_words=True 가 전달돼야 한다
        fake_tokenizer, fake_model = self._prepare(tmp_path, monkeypatch)
        # 토크나이저 호출 결과: word_ids() 가짜 반환
        encoded = MagicMock()
        encoded.word_ids = MagicMock(return_value=[None, 0, 1, 2, None])
        # ** 언패킹 가능하도록 keys/getitem 동작 부여
        encoded.__iter__ = lambda self: iter([])
        encoded.keys = MagicMock(return_value=[])
        fake_tokenizer.return_value = encoded
        # model(**inputs) 호출 결과 — logits 가짜
        outputs = MagicMock()
        # 글자 3개 + special 2개 = 시퀀스 길이 5, 라벨 수 5
        # 가장 큰 logit 인덱스가 모두 0 (=O) 이도록
        outputs.logits = _FakeLogits(seq_len=5, n_labels=5, argmax_index=0)
        fake_model.return_value = outputs

        inst = L5Layer(model_name="charlevel-ner")

        captured = {}

        def _fake_call(chars, **kwargs):
            captured["chars"] = chars
            captured["kwargs"] = kwargs
            return encoded

        fake_tokenizer.side_effect = _fake_call

        inst._adapter.predict("ab")

        assert captured["kwargs"].get("is_split_into_words") is True

    def test_pipeline_not_used_for_charlevel(self, tmp_path, monkeypatch):
        # charlevel 어댑터는 transformers.pipeline 을 호출하면 안 된다
        _write_charlevel_model_dir(tmp_path, name="charlevel-ner")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        pipeline_calls = {"count": 0}

        def _spy_pipeline(*args, **kwargs):
            pipeline_calls["count"] += 1
            return MagicMock()

        monkeypatch.setattr(l5_mod, "pipeline", _spy_pipeline)
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(return_value=fake_tokenizer)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock(return_value=fake_model)),
            raising=False,
        )

        L5Layer(model_name="charlevel-ner")

        # charlevel 경로는 pipeline 을 쓰지 않으므로 호출 횟수 0
        assert pipeline_calls["count"] == 0


class _FakeLogits:
    """torch.argmax(logits, dim=-1) 같은 호출에 응답하는 가짜 텐서.

    어댑터 구현이 어떤 라이브러리 호출 패턴을 쓰든 _predict_chunk 를
    monkeypatch 로 우회하기 때문에 실제로 사용되지 않을 가능성이 높다.
    """

    def __init__(self, seq_len, n_labels, argmax_index):
        self.seq_len = seq_len
        self.n_labels = n_labels
        self.argmax_index = argmax_index
        self.shape = (1, seq_len, n_labels)


class TestHFCharLevelChunking:
    """긴 입력의 문장 단위 청크 분할."""

    def _prepare(self, tmp_path, monkeypatch, max_length=256):
        _write_charlevel_model_dir(
            tmp_path,
            name="charlevel-ner",
            max_length=max_length,
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(return_value=fake_tokenizer)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock(return_value=fake_model)),
            raising=False,
        )
        return fake_tokenizer, fake_model

    def test_short_input_single_chunk(self, tmp_path, monkeypatch):
        # 짧은 입력은 _predict_chunk 가 한 번만 호출됨
        self._prepare(tmp_path, monkeypatch, max_length=256)
        inst = L5Layer(model_name="charlevel-ner")

        chunk_calls = []

        def _spy_chunk(chars):
            chunk_calls.append(list(chars))
            return [("O", 1.0)] * len(chars)

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        inst._adapter.predict("짧은 문장 하나입니다")

        assert len(chunk_calls) == 1

    def test_long_input_split_into_multiple_chunks(self, tmp_path, monkeypatch):
        # max_length 가 작으면 문장 부호 기준으로 여러 청크로 분할
        self._prepare(tmp_path, monkeypatch, max_length=8)
        inst = L5Layer(model_name="charlevel-ner")

        chunk_calls = []

        def _spy_chunk(chars):
            chunk_calls.append(list(chars))
            return [("O", 1.0)] * len(chars)

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        # 문장 부호로 명확히 분할 가능한 텍스트
        inst._adapter.predict(
            "첫 번째 문장. 두 번째 문장! 세 번째 문장? 네 번째 문장."
        )

        # 여러 청크로 분할됐어야 한다
        assert len(chunk_calls) >= 2

    def test_chunked_labels_concatenated_to_full_sequence(
        self, tmp_path, monkeypatch
    ):
        # 청크별 라벨 결과가 합쳐져 전체 글자 시퀀스를 복원해야 한다
        self._prepare(tmp_path, monkeypatch, max_length=8)
        inst = L5Layer(model_name="charlevel-ner")

        # 각 청크에 대해 모두 O 라벨 반환 → 합쳐진 길이가 전체 글자 수와 일치
        def _spy_chunk(chars):
            return [("O", 1.0)] * len(chars)

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = inst._adapter.predict("한 문장입니다. 두 번째 문장입니다.")

        # 라벨이 모두 O 이므로 엔티티가 없어야 한다 (BIO 디코딩 결과 [])
        assert result == []


class TestHFCharLevelBridge:
    """[SP] 토큰 공백 브릿지 후처리."""

    def _prepare(self, tmp_path, monkeypatch):
        _write_charlevel_model_dir(tmp_path, name="charlevel-ner")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(return_value=fake_tokenizer)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock(return_value=fake_model)),
            raising=False,
        )

    def test_sp_o_between_same_entity_bridged(self, tmp_path, monkeypatch):
        # [SP] 위치가 O 인데 양쪽이 같은 엔티티 PS → I-PS 로 보정되어
        # 두 토막이 하나의 엔티티로 합쳐져야 한다
        self._prepare(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        # "홍 길동" → ["홍", "[SP]", "길", "동"]
        # 라벨: B-PS, O, I-PS, I-PS — 보정 후 B-PS, I-PS, I-PS, I-PS
        def _spy_chunk(chars):
            return [
                ("B-PS", 0.99),
                ("O", 0.6),
                ("I-PS", 0.98),
                ("I-PS", 0.97),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = inst._adapter.predict("홍 길동")

        # 단일 PS 엔티티로 디코딩
        assert len(result) == 1
        assert result[0]["entity"] == "PS"
        # word 는 원본 텍스트에서 잘라낸 슬라이스
        assert result[0]["word"] == "홍 길동"
        assert result[0]["start"] == 0

    def test_sp_o_between_different_entities_not_bridged(
        self, tmp_path, monkeypatch
    ):
        # [SP] 양쪽이 다른 엔티티 → 보정 없음 → 두 엔티티로 분리
        self._prepare(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        # "홍 010" → ["홍", "[SP]", "0", "1", "0"]
        # 라벨: B-PS, O, B-PHONE, I-PHONE, I-PHONE
        def _spy_chunk(chars):
            return [
                ("B-PS", 0.99),
                ("O", 0.7),
                ("B-PHONE", 0.95),
                ("I-PHONE", 0.94),
                ("I-PHONE", 0.93),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = inst._adapter.predict("홍 010")

        # PS, PHONE 두 엔티티로 분리
        assert len(result) == 2
        types = {r["entity"] for r in result}
        assert types == {"PS", "PHONE"}

    def test_sp_o_with_one_side_o_not_bridged(self, tmp_path, monkeypatch):
        # 한쪽이 O 면 보정 없음
        self._prepare(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        # 라벨: B-PS, O, O, I-PS — 양쪽 같은 PS 가 아니라 한쪽이 O 라
        # 단순 인접 O 케이스로 취급, 보정 없음
        def _spy_chunk(chars):
            return [
                ("B-PS", 0.99),
                ("O", 0.5),
                ("O", 0.5),
                ("I-PS", 0.9),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = inst._adapter.predict("ab cd")

        # 보정이 없으므로 첫 PS (B-PS 단독) 만 엔티티가 됨
        # I-PS 가 B 없이 등장한 것은 디코더가 새 엔티티로 시작 처리할 수도 있어
        # 어댑터 구현에 따라 1~2개 가능. 핵심은 "다리 없음" — 단일 엔티티로
        # 합쳐지면 안 된다는 것
        assert len(result) >= 1
        # 합쳐진 단일 엔티티의 word 가 전체 5글자가 되면 안 된다
        assert all(r["word"] != "ab cd" for r in result)


class TestHFCharLevelDecoding:
    """글자별 BIO 라벨에서 엔티티 스팬 디코딩."""

    def _prepare(self, tmp_path, monkeypatch):
        _write_charlevel_model_dir(tmp_path, name="charlevel-ner")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(return_value=fake_tokenizer)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock(return_value=fake_model)),
            raising=False,
        )

    def test_consecutive_bio_becomes_single_entity(self, tmp_path, monkeypatch):
        # B-PS, I-PS, I-PS → 1개 엔티티 PS
        self._prepare(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        def _spy_chunk(chars):
            return [
                ("B-PS", 0.99),
                ("I-PS", 0.98),
                ("I-PS", 0.97),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = inst._adapter.predict("홍길동")

        assert len(result) == 1
        assert result[0]["entity"] == "PS"
        assert result[0]["word"] == "홍길동"
        assert result[0]["start"] == 0

    def test_o_separates_entities(self, tmp_path, monkeypatch):
        # B-PS, I-PS, O, B-PS, I-PS → 2개 엔티티
        self._prepare(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        def _spy_chunk(chars):
            return [
                ("B-PS", 0.99),
                ("I-PS", 0.98),
                ("O", 0.95),
                ("B-PS", 0.97),
                ("I-PS", 0.96),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = inst._adapter.predict("홍길a김철")

        assert len(result) == 2
        assert all(r["entity"] == "PS" for r in result)

    def test_output_has_hf_style_keys(self, tmp_path, monkeypatch):
        # 출력 dict 는 entity / word / start / score 키를 가진다
        self._prepare(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        def _spy_chunk(chars):
            return [
                ("B-PS", 0.95),
                ("I-PS", 0.92),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = inst._adapter.predict("홍길")

        assert len(result) == 1
        ent = result[0]
        for key in ("entity", "word", "start", "score"):
            assert key in ent
        assert isinstance(ent["entity"], str)
        assert isinstance(ent["word"], str)
        assert isinstance(ent["start"], int)
        assert isinstance(ent["score"], float)

    def test_score_is_minimum_in_span(self, tmp_path, monkeypatch):
        # span 내 글자 score 의 최솟값을 엔티티 score 로 사용 (가장 보수적)
        self._prepare(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        def _spy_chunk(chars):
            return [
                ("B-PS", 0.99),
                ("I-PS", 0.55),
                ("I-PS", 0.88),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = inst._adapter.predict("홍길동")

        assert len(result) == 1
        assert result[0]["score"] == pytest.approx(0.55)


class TestAdapterOutputNormalization:
    """어댑터별 출력 키가 _check_ner 와 호환되는지 확인."""

    def _prepare_charlevel(self, tmp_path, monkeypatch):
        _write_charlevel_model_dir(
            tmp_path,
            name="charlevel-ner",
            label_map={"PS": "person"},
            block_singletons=["person"],
            min_score=0.5,
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(return_value=fake_tokenizer)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock(return_value=fake_model)),
            raising=False,
        )

    def test_charlevel_keys_match_pipeline_style(self, tmp_path, monkeypatch):
        # _HFCharLevelAdapter.predict 와 _HFPipelineAdapter.predict 가
        # 같은 키 집합을 노출 (entity, word, start, score)
        self._prepare_charlevel(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        def _spy_chunk(chars):
            return [
                ("B-PS", 0.95),
                ("I-PS", 0.92),
                ("I-PS", 0.91),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        char_out = inst._adapter.predict("홍길동")
        assert char_out
        char_keys = set(char_out[0].keys())
        # 최소한 이 4개 키는 보장
        assert {"entity", "word", "start", "score"}.issubset(char_keys)

    async def test_charlevel_entity_flows_into_check_ner(
        self, tmp_path, monkeypatch
    ):
        # 어댑터가 반환한 엔티티가 _check_ner 의 singleton 차단에 도달
        self._prepare_charlevel(tmp_path, monkeypatch)
        inst = L5Layer(model_name="charlevel-ner")

        def _spy_chunk(chars):
            return [
                ("B-PS", 0.95),
                ("I-PS", 0.92),
                ("I-PS", 0.91),
            ]

        monkeypatch.setattr(
            inst._adapter,
            "_predict_chunk",
            _spy_chunk,
            raising=False,
        )

        result = await inst.check(_req("홍길동"))

        assert result.allowed is False
        assert "person" in result.tags
        assert "ner" in result.tags
        assert "PII detected: person" in result.reason


class TestFallbackForcesHFPipeline:
    """pii_labels.json 부재 시 어댑터는 hf-pipeline 강제."""

    def test_no_json_uses_pipeline_adapter(self, tmp_path, monkeypatch):
        # JSON 부재 → 폴백 → 어댑터는 _HFPipelineAdapter 로 강제
        # (글자 단위 학습 모델은 폴백 불가능하므로 charlevel 로 갈 수 없음)
        model_dir = tmp_path / "fallback-no-json"
        model_dir.mkdir()
        (model_dir / "config.json").write_text(
            json.dumps(
                {
                    "id2label": {
                        "0": "O",
                        "1": "B-PS",
                        "2": "I-PS",
                    }
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)

        inst = L5Layer(model_name="fallback-no-json")

        # 폴백 경로에서도 _adapter 가 _HFPipelineAdapter 여야 한다
        assert inst._adapter is not None
        assert isinstance(inst._adapter, l5_mod._HFPipelineAdapter)


class TestHFPipelineAdapterParity:
    """기존 hf-pipeline 동작이 어댑터로 옮겨져도 동일하게 작동."""

    def test_pipeline_adapter_predict_returns_pipeline_call_result(
        self, tmp_path, monkeypatch
    ):
        # _HFPipelineAdapter.predict(text) 는 내부 pipeline(text) 결과를
        # 그대로 (혹은 entity_group → entity 키 매핑만 거쳐) 반환한다
        model_dir = tmp_path / "pipeline-adapter"
        model_dir.mkdir()
        (model_dir / "config.json").write_text(
            json.dumps({"id2label": {"0": "O", "1": "B-PS"}}),
            encoding="utf-8",
        )
        (model_dir / "pii_labels.json").write_text(
            json.dumps(
                {
                    "adapter": "hf-pipeline",
                    "label_map": {"PS": "person"},
                    "block_singletons": ["person"],
                    "block_combinations": [],
                    "min_score": 0.5,
                    "aggregation_strategy": "simple",
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)

        # pipeline 호출 결과로 가짜 엔티티 반환
        fake_pipeline = MagicMock()
        fake_pipeline.return_value = [
            {
                "entity_group": "PS",
                "word": "홍길동",
                "start": 0,
                "end": 3,
                "score": 0.97,
            },
        ]
        monkeypatch.setattr(
            l5_mod,
            "pipeline",
            lambda *args, **kwargs: fake_pipeline,
        )

        inst = L5Layer(model_name="pipeline-adapter")

        out = inst._adapter.predict("홍길동")

        assert isinstance(out, list)
        assert len(out) == 1
        # entity 키가 노출돼야 한다 (entity_group → entity 정규화)
        assert "entity" in out[0]
        # 정규화된 라벨 또는 원본 라벨 어느 쪽이든 PS 가 포함돼야 한다
        assert "PS" in out[0]["entity"]


# ──────────────────────────────────────────────
# 9. GLiNER 어댑터 — dispatch / 로딩 / 6 개선안 통합
# ──────────────────────────────────────────────
#
# 본 섹션은 _GLinerAdapter 를 신설하면서 도입되는 다음 6 개선안을
# 어댑터 동작 차원에서 강제한다.
#
# 1) inference_labels 는 약 10 개로 제한 권장. max_types 안이면 단일
#    호출, 초과하면 라벨 청크로 분할 호출
# 2) 카테고리별 차등 임계값(category_thresholds) + default_threshold
# 3) 이중 단계 임계값 — pre_threshold(기본 0.4) 로 후보 수집,
#    카테고리 cut 으로 2차 필터
# 4) 후처리 오탐 필터 (한국어 PII 특화)
# 5) 슬라이딩 윈도우 텍스트 청크 (text_window_max_len + overlap)
# 6) 윈도우 결과 (start, end) span dedup
#
# 추가 인프라:
# - DeBERTa-v3 tokenizer 호환 레이어 (PreTrainedTokenizerFast 우회)
# - words_splitter override
# - inference_labels 미존재 / 알 수 없는 adapter 값 fail-open


_GLINER_LABEL_MAP_FULL = {
    "사람 이름": "person",
    "기관명": "organization",
    "주소": "address",
    "위치명": "location",
    "직업명": "job_title",
    "거래내역": "transaction",
    "대출정보": "loan",
    "신용등급": "credit_rating",
    "재산및소득정보": "income_property",
    "IT시스템정보": "it_system",
}


_GLINER_INFERENCE_LABELS_FULL = list(_GLINER_LABEL_MAP_FULL.keys())


_GLINER_CATEGORY_THRESHOLDS_FULL = {
    "person": 0.65,
    "organization": 0.70,
    "address": 0.70,
    "location": 0.75,
    "job_title": 0.80,
    "transaction": 0.80,
    "loan": 0.80,
    "credit_rating": 0.85,
    "income_property": 0.80,
    "it_system": 0.80,
}


def _write_gliner_model_dir(
    tmp_path,
    name="gliner-ner",
    *,
    label_map=None,
    inference_labels=None,
    category_thresholds=None,
    default_threshold=None,
    pre_threshold=None,
    block_singletons=None,
    block_combinations=None,
    min_score=0.0,
    max_length=256,
    text_window_max_len=None,
    text_window_overlap=None,
    words_splitter=None,
    omit_inference_labels=False,
    adapter="gliner",
    gliner_config_max_types=10,
):
    """GLiNER 어댑터용 모델 폴더와 pii_labels.json 생성.

    omit_inference_labels=True 이면 inference_labels 키 자체를 빼서
    어댑터의 fail-open 경로를 검증할 수 있다.
    """
    model_dir = tmp_path / name
    model_dir.mkdir()
    # GLiNER 모델은 gliner_config.json 을 가진다
    (model_dir / "gliner_config.json").write_text(
        json.dumps({"max_types": gliner_config_max_types}),
        encoding="utf-8",
    )
    # config.json 도 폴백 경로 호환성 유지를 위해 둠
    (model_dir / "config.json").write_text(
        json.dumps({"id2label": {"0": "O"}}),
        encoding="utf-8",
    )

    spec = {
        "label_map": (
            dict(label_map)
            if label_map is not None
            else dict(_GLINER_LABEL_MAP_FULL)
        ),
        "block_singletons": (
            list(block_singletons)
            if block_singletons is not None
            else ["person", "address", "location"]
        ),
        "block_combinations": (
            block_combinations if block_combinations is not None else []
        ),
        "min_score": min_score,
        "max_length": max_length,
    }
    if adapter is not None:
        spec["adapter"] = adapter
    if not omit_inference_labels:
        spec["inference_labels"] = (
            list(inference_labels)
            if inference_labels is not None
            else list(_GLINER_INFERENCE_LABELS_FULL)
        )
    if category_thresholds is not None:
        spec["category_thresholds"] = dict(category_thresholds)
    if default_threshold is not None:
        spec["default_threshold"] = default_threshold
    if pre_threshold is not None:
        spec["pre_threshold"] = pre_threshold
    if text_window_max_len is not None:
        spec["text_window_max_len"] = text_window_max_len
    if text_window_overlap is not None:
        spec["text_window_overlap"] = text_window_overlap
    if words_splitter is not None:
        spec["words_splitter"] = words_splitter

    (model_dir / "pii_labels.json").write_text(
        json.dumps(spec, ensure_ascii=False),
        encoding="utf-8",
    )
    return model_dir


def _make_fake_gliner_model(predict_return=None):
    """GLiNER 모델 모형 — predict_entities 가 주어진 값을 반환."""
    fake_model = MagicMock()
    # data_processor.words_splitter 교체 검증용 속성
    fake_model.data_processor = MagicMock()
    fake_model.data_processor.words_splitter = MagicMock(
        name="default-splitter"
    )
    # 평가 모드
    fake_model.eval = MagicMock(return_value=fake_model)
    # 기본 predict_entities — 빈 리스트
    if predict_return is None:
        fake_model.predict_entities = MagicMock(return_value=[])
    else:
        fake_model.predict_entities = MagicMock(return_value=predict_return)
    # config.max_len 같은 속성도 일부 어댑터 구현이 참조할 수 있음
    fake_model.config = MagicMock()
    fake_model.config.max_len = 384
    return fake_model


def _patch_gliner(monkeypatch, fake_model=None, predict_return=None):
    """gliner.GLiNER.from_pretrained 를 가짜로 치환한다.

    어댑터 구현이 ``from gliner import GLiNER`` 또는
    ``import gliner`` 후 ``gliner.GLiNER.from_pretrained`` 두 형태 모두
    감지하도록 양쪽을 함께 monkeypatch.
    """
    import gliner as gliner_pkg

    if fake_model is None:
        fake_model = _make_fake_gliner_model(predict_return=predict_return)
    from_pretrained = MagicMock(return_value=fake_model)
    monkeypatch.setattr(
        gliner_pkg.GLiNER,
        "from_pretrained",
        from_pretrained,
    )
    return fake_model, from_pretrained


def _patch_pretrained_tokenizer_fast(monkeypatch):
    """transformers.PreTrainedTokenizerFast.from_pretrained 를 가짜로 치환."""
    from transformers import PreTrainedTokenizerFast

    fake_tokenizer = MagicMock(name="fast-tokenizer")
    from_pretrained = MagicMock(return_value=fake_tokenizer)
    monkeypatch.setattr(
        PreTrainedTokenizerFast,
        "from_pretrained",
        from_pretrained,
    )
    return fake_tokenizer, from_pretrained


def _make_gliner_adapter(tmp_path, monkeypatch, **kwargs):
    """_GLinerAdapter 를 직접 생성해 반환하는 헬퍼.

    L5Layer 를 거치지 않고 어댑터 단위 동작을 검증할 때 사용.
    """
    fake_model = kwargs.pop("fake_model", None)
    predict_return = kwargs.pop("predict_return", None)
    name = kwargs.pop("name", "gliner-direct")
    model_dir = _write_gliner_model_dir(tmp_path, name=name, **kwargs)
    monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
    fake_model, _ = _patch_gliner(
        monkeypatch,
        fake_model=fake_model,
        predict_return=predict_return,
    )
    _patch_pretrained_tokenizer_fast(monkeypatch)

    spec_path = model_dir / "pii_labels.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    adapter = l5_mod._GLinerAdapter(model_dir, spec)
    return adapter, fake_model, spec


# ──────────────────────────────────────────────
# 9.A. GLiNER dispatch — _load_ner_model 분기
# ──────────────────────────────────────────────


class TestGLinerDispatch:
    """pii_labels.json 의 adapter='gliner' 가 _GLinerAdapter 로 분기."""

    def test_gliner_adapter_dispatched(self, tmp_path, monkeypatch):
        # adapter='gliner' → _GLinerAdapter 인스턴스
        _write_gliner_model_dir(tmp_path, name="gliner-disp")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        _patch_gliner(monkeypatch)
        _patch_pretrained_tokenizer_fast(monkeypatch)

        inst = L5Layer(model_name="gliner-disp")

        # 모듈 최상단에 _GLinerAdapter 클래스가 정의되어 있어야 한다
        assert hasattr(l5_mod, "_GLinerAdapter")
        assert inst._adapter is not None
        assert isinstance(inst._adapter, l5_mod._GLinerAdapter)

    def test_hf_pipeline_dispatch_unaffected(self, tmp_path, monkeypatch):
        # GLiNER 추가가 hf-pipeline 분기를 깨뜨리지 않는다
        _write_charlevel_model_dir(
            tmp_path,
            name="pipeline-still-works",
            adapter="hf-pipeline",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)

        inst = L5Layer(model_name="pipeline-still-works")

        assert isinstance(inst._adapter, l5_mod._HFPipelineAdapter)

    def test_hf_charlevel_dispatch_unaffected(self, tmp_path, monkeypatch):
        # GLiNER 추가가 hf-charlevel 분기를 깨뜨리지 않는다
        _write_charlevel_model_dir(tmp_path, name="charlevel-still-works")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(return_value=fake_tokenizer)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock(return_value=fake_model)),
            raising=False,
        )

        inst = L5Layer(model_name="charlevel-still-works")

        assert isinstance(inst._adapter, l5_mod._HFCharLevelAdapter)


# ──────────────────────────────────────────────
# 9.B. GLiNER 어댑터 로딩
# ──────────────────────────────────────────────


class TestGLinerAdapterLoading:
    """_GLinerAdapter 생성자 동작."""

    def test_calls_gliner_from_pretrained(self, tmp_path, monkeypatch):
        # gliner.GLiNER.from_pretrained 가 모델 폴더 경로로 호출됨
        model_dir = _write_gliner_model_dir(tmp_path, name="gliner-load")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        _, from_pretrained = _patch_gliner(monkeypatch)
        _patch_pretrained_tokenizer_fast(monkeypatch)

        L5Layer(model_name="gliner-load")

        assert from_pretrained.called
        # from_pretrained 의 첫 번째 인자에 모델 폴더 경로가 들어가야 한다
        call_args = from_pretrained.call_args_list[0]
        passed = list(call_args.args) + list(call_args.kwargs.values())
        assert any(str(model_dir) in str(arg) for arg in passed)

    def test_missing_inference_labels_is_fail_open(self, tmp_path, monkeypatch):
        # inference_labels 가 spec 에 없으면 어댑터 생성 거부 → fail-open
        _write_gliner_model_dir(
            tmp_path,
            name="gliner-no-labels",
            omit_inference_labels=True,
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        _patch_gliner(monkeypatch)
        _patch_pretrained_tokenizer_fast(monkeypatch)

        inst = L5Layer(model_name="gliner-no-labels")

        assert inst._adapter is None
        assert inst._ner_model is None

    def test_deberta_compat_layer_uses_pretrained_tokenizer_fast(
        self, tmp_path, monkeypatch
    ):
        # DeBERTa-v3 호환 레이어: BaseGLiNER._load_tokenizer 가 호출되면
        # 그 내부 구현이 PreTrainedTokenizerFast.from_pretrained 를
        # 사용하도록 어댑터가 교체해 두어야 한다
        from gliner.model import BaseGLiNER

        _write_gliner_model_dir(tmp_path, name="gliner-deberta")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        _patch_gliner(monkeypatch)
        _, fast_from_pretrained = _patch_pretrained_tokenizer_fast(monkeypatch)

        # 어댑터 로드 (이 시점에 BaseGLiNER._load_tokenizer 가 교체됨)
        L5Layer(model_name="gliner-deberta")

        # 교체된 _load_tokenizer 를 직접 호출해 PreTrainedTokenizerFast 가
        # 쓰이는지 확인
        from gliner.config import GLiNERConfig

        fake_config = MagicMock(spec=GLiNERConfig)
        # 호출 자체로 fast tokenizer 경로를 타야 한다 — 실패하면
        # 호환 레이어가 활성화되지 않은 것
        # 내부 후처리 단계에서 예외가 나도 호출 자체는 발생했어야 한다
        with contextlib.suppress(Exception):
            BaseGLiNER._load_tokenizer(
                fake_config,
                tmp_path / "gliner-deberta",
            )

        assert fast_from_pretrained.called

    def test_words_splitter_override(self, tmp_path, monkeypatch):
        # spec.words_splitter 가 있으면 model.data_processor.words_splitter
        # 가 새 splitter 객체로 교체된다
        _write_gliner_model_dir(
            tmp_path,
            name="gliner-mecab",
            words_splitter="mecab",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_model, _ = _patch_gliner(monkeypatch)
        original_splitter = fake_model.data_processor.words_splitter
        _patch_pretrained_tokenizer_fast(monkeypatch)

        # WordsSplitter 호출을 추적
        from gliner.data_processing import WordsSplitter

        new_splitter = MagicMock(name="mecab-splitter")
        # 일부 구현은 WordsSplitter("mecab") 처럼 type 으로 인스턴스 생성
        monkeypatch.setattr(
            WordsSplitter,
            "__new__",
            staticmethod(lambda cls, *a, **kw: new_splitter),
            raising=False,
        )

        L5Layer(model_name="gliner-mecab")

        # 교체 후 splitter 가 원래 것과 달라야 한다
        assert fake_model.data_processor.words_splitter is not original_splitter

    def test_words_splitter_omitted_keeps_default(self, tmp_path, monkeypatch):
        # words_splitter 가 spec 에 없으면 model.data_processor.words_splitter
        # 는 그대로 유지된다
        _write_gliner_model_dir(
            tmp_path,
            name="gliner-default-splitter",
            words_splitter=None,
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_model, _ = _patch_gliner(monkeypatch)
        original_splitter = fake_model.data_processor.words_splitter
        _patch_pretrained_tokenizer_fast(monkeypatch)

        L5Layer(model_name="gliner-default-splitter")

        assert fake_model.data_processor.words_splitter is original_splitter

    def test_gliner_load_failure_is_fail_open(self, tmp_path, monkeypatch):
        # GLiNER.from_pretrained 가 예외 → fail-open
        _write_gliner_model_dir(tmp_path, name="gliner-boom")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)

        import gliner as gliner_pkg

        def _boom(*args, **kwargs):
            msg = "GLiNER load failed"
            raise RuntimeError(msg)

        monkeypatch.setattr(gliner_pkg.GLiNER, "from_pretrained", _boom)
        _patch_pretrained_tokenizer_fast(monkeypatch)

        inst = L5Layer(model_name="gliner-boom")

        assert inst._adapter is None
        assert inst._ner_model is None


# ──────────────────────────────────────────────
# 9.C. 라벨 청크 분할 (max_types 폴백)
# ──────────────────────────────────────────────


class TestGLinerLabelChunking:
    """inference_labels 길이가 max_types 안/밖일 때 호출 패턴."""

    def test_labels_within_max_types_single_call(self, tmp_path, monkeypatch):
        # inference_labels = 5개, max_types = 10 → predict_entities 1회 호출
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-fits",
            inference_labels=[
                "사람 이름",
                "기관명",
                "주소",
                "위치명",
                "직업명",
            ],
            label_map={
                "사람 이름": "person",
                "기관명": "organization",
                "주소": "address",
                "위치명": "location",
                "직업명": "job_title",
            },
            gliner_config_max_types=10,
        )

        adapter.predict("간단한 한국어 입력")

        # 단일 라벨 청크 → predict_entities 1회 (텍스트 윈도우도 1)
        assert fake_model.predict_entities.call_count == 1

    def test_labels_exceeding_max_types_split_into_chunks(
        self, tmp_path, monkeypatch
    ):
        # inference_labels = 12개, max_types = 5 → predict_entities 가
        # 라벨 청크 단위로 여러 번 호출됨 (한 텍스트 윈도우 내)
        many_labels = [f"라벨{i}" for i in range(12)]
        many_label_map = {
            label: f"type{i}" for i, label in enumerate(many_labels)
        }
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-too-many",
            inference_labels=many_labels,
            label_map=many_label_map,
            block_singletons=[],
            gliner_config_max_types=5,
        )

        adapter.predict("간단한 한국어 입력")

        # 12 / 5 = ceil 3 청크 이상 호출되어야 함
        assert fake_model.predict_entities.call_count >= 3


# ──────────────────────────────────────────────
# 9.D. 슬라이딩 윈도우 텍스트 청크
# ──────────────────────────────────────────────


class TestGLinerTextWindowing:
    """text_window_max_len + overlap 기반 슬라이딩 윈도우."""

    def test_short_text_single_window(self, tmp_path, monkeypatch):
        # 짧은 텍스트 → 단일 윈도우 → predict_entities 1회 호출
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-short",
            text_window_max_len=64,
            text_window_overlap=8,
            gliner_config_max_types=10,
        )

        adapter.predict("짧은 입력")

        assert fake_model.predict_entities.call_count == 1

    def test_long_text_split_into_multiple_windows(self, tmp_path, monkeypatch):
        # 긴 텍스트 → 여러 윈도우로 분할 → predict_entities 가 여러 번
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-long",
            text_window_max_len=20,
            text_window_overlap=4,
            gliner_config_max_types=10,
        )

        long_text = "가" * 200
        adapter.predict(long_text)

        # 200 글자에 max_len=20, overlap=4 → 윈도우 여러 개
        assert fake_model.predict_entities.call_count >= 5

    def test_split_into_text_windows_helper_returns_overlapping_ranges(
        self, tmp_path, monkeypatch
    ):
        # _split_into_text_windows 헬퍼가 (start, end) 튜플 리스트를 반환,
        # 인접 윈도우는 overlap 만큼 겹침
        adapter, _, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-split",
            text_window_max_len=10,
            text_window_overlap=3,
            gliner_config_max_types=10,
        )

        # 어댑터에 슬라이딩 윈도우 헬퍼가 노출되어야 한다
        assert hasattr(adapter, "_split_into_text_windows")
        ranges = adapter._split_into_text_windows("a" * 30, 10, 3)

        assert isinstance(ranges, list)
        assert len(ranges) >= 2
        # 첫 윈도우 시작은 0
        assert ranges[0][0] == 0
        # 마지막 윈도우 끝은 텍스트 길이 이상이어야 한다
        assert ranges[-1][1] >= 30
        # 인접 윈도우 겹침 검증
        for prev, cur in itertools.pairwise(ranges):
            assert cur[0] < prev[1]

    def test_short_text_returns_single_window(self, tmp_path, monkeypatch):
        # _split_into_text_windows 의 입력 길이가 max_len 이하면 단일 윈도우
        adapter, _, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-onewin",
            text_window_max_len=100,
            text_window_overlap=10,
            gliner_config_max_types=10,
        )

        ranges = adapter._split_into_text_windows("짧은", 100, 10)

        assert ranges == [(0, len("짧은"))]

    def test_window_local_offset_mapped_to_global(self, tmp_path, monkeypatch):
        # 두 번째 윈도우에서 잡힌 엔티티의 (start, end) 가 전역 좌표로
        # 정확히 매핑되어야 한다
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-offset",
            text_window_max_len=10,
            text_window_overlap=2,
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.0},
            default_threshold=0.0,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )

        # 윈도우별로 다른 결과를 반환하는 side_effect 구성.
        # 첫 윈도우는 빈, 두 번째 윈도우(local_start=8 가정) 에서
        # local start=2, end=5 의 엔티티 → 전역 start=10, end=13
        call_log = []

        def _predict(text, **kwargs):
            call_log.append(text)
            if len(call_log) == 2:
                return [
                    {
                        "label": "사람 이름",
                        "text": "홍길동",
                        "start": 2,
                        "end": 5,
                        "score": 0.9,
                    }
                ]
            return []

        fake_model.predict_entities.side_effect = _predict

        # 30글자 입력 → 윈도우 여러 개
        result = adapter.predict("한" * 30)

        assert any(
            r.get("entity") == "person" and r.get("start", -1) >= 8
            for r in result
        )

    def test_dedup_same_span_across_windows(self, tmp_path, monkeypatch):
        # 같은 (start, end) 가 여러 윈도우에서 잡혀도 1개만 남고,
        # score 가 가장 높은 라벨 유지
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-dedup",
            text_window_max_len=20,
            text_window_overlap=10,
            inference_labels=["사람 이름", "기관명"],
            label_map={
                "사람 이름": "person",
                "기관명": "organization",
            },
            block_singletons=[],
            category_thresholds={"person": 0.0, "organization": 0.0},
            default_threshold=0.0,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )

        # 모든 윈도우에서 동일 전역 span (start=0, end=3, "홍길동") 반환
        # 단, 한 번은 score 0.9 (사람 이름), 한 번은 score 0.5 (기관명)
        scores = iter([0.9, 0.5, 0.4])
        labels = iter(["사람 이름", "기관명", "사람 이름"])

        def _predict(text, **kwargs):
            try:
                s = next(scores)
                lab = next(labels)
            except StopIteration:
                return []
            return [
                {
                    "label": lab,
                    "text": "홍길동",
                    "start": 0,
                    "end": 3,
                    "score": s,
                }
            ]

        fake_model.predict_entities.side_effect = _predict

        result = adapter.predict("홍길동" + "가" * 50)

        # 같은 span (0, 3) 은 한 개만 남아야 한다
        spans = [
            (r["start"], r.get("end", r["start"] + len(r["word"])))
            for r in result
            if (r["start"], r.get("end", -1)) == (0, 3)
        ]
        assert len(spans) <= 1
        # 최고 점수 라벨(사람 이름→person) 이 유지돼야 한다
        if spans:
            keep = next(r for r in result if r["start"] == 0)
            assert keep["entity"] == "person"


# ──────────────────────────────────────────────
# 9.E. 카테고리별 차등 임계값
# ──────────────────────────────────────────────


class TestGLinerCategoryThresholds:
    """category_thresholds + default_threshold 적용."""

    def test_per_label_cut_drops_below_threshold(self, tmp_path, monkeypatch):
        # person cut 0.65 미만은 제거
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-cat-cut",
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.65},
            default_threshold=0.5,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )

        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "홍",
                "start": 0,
                "end": 1,
                "score": 0.40,  # 0.65 미만 → 제거
            }
        ]

        result = adapter.predict("홍이 좋아한다")

        assert all(r.get("entity") != "person" for r in result)

    def test_per_label_cut_keeps_above_threshold(self, tmp_path, monkeypatch):
        # credit_rating cut 0.85 이상만 유지
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-cat-keep",
            inference_labels=["신용등급"],
            label_map={"신용등급": "credit_rating"},
            block_singletons=["credit_rating"],
            category_thresholds={"credit_rating": 0.85},
            default_threshold=0.5,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )

        fake_model.predict_entities.return_value = [
            {
                "label": "신용등급",
                "text": "AAA등급 신용",
                "start": 0,
                "end": 7,
                "score": 0.90,  # 0.85 이상 → 유지
            }
        ]

        result = adapter.predict("AAA등급 신용 안내")

        assert any(r.get("entity") == "credit_rating" for r in result)

    def test_default_threshold_for_unlisted_label(self, tmp_path, monkeypatch):
        # category_thresholds 에 없는 라벨 → default_threshold 적용
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-default-cut",
            inference_labels=["IT시스템정보"],
            label_map={"IT시스템정보": "it_system"},
            block_singletons=["it_system"],
            category_thresholds={},  # 아무것도 명시 안 함
            default_threshold=0.75,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )

        # 0.6 → default 0.75 미만 → 제거
        fake_model.predict_entities.return_value = [
            {
                "label": "IT시스템정보",
                "text": "AWS-VPC-prod-cluster-42",
                "start": 0,
                "end": 23,
                "score": 0.6,
            }
        ]

        result = adapter.predict("로그 시스템 정보 출력")

        assert all(r.get("entity") != "it_system" for r in result)

    def test_default_threshold_defaults_to_0_75(self, tmp_path, monkeypatch):
        # spec 에 default_threshold 가 없으면 기본값 0.75 가 사용된다
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-default-imp",
            inference_labels=["대출정보"],
            label_map={"대출정보": "loan"},
            block_singletons=["loan"],
            category_thresholds={},
            default_threshold=None,  # spec 에서 누락
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )

        # 0.74 → 0.75 기본 cut 미만 → 제거
        fake_model.predict_entities.return_value = [
            {
                "label": "대출정보",
                "text": "주택담보대출 5억",
                "start": 0,
                "end": 8,
                "score": 0.74,
            }
        ]
        out_low = adapter.predict("대출 안내")
        assert all(r.get("entity") != "loan" for r in out_low)

        # 0.80 → 통과
        fake_model.predict_entities.return_value = [
            {
                "label": "대출정보",
                "text": "주택담보대출 5억",
                "start": 0,
                "end": 8,
                "score": 0.80,
            }
        ]
        out_high = adapter.predict("대출 안내")
        assert any(r.get("entity") == "loan" for r in out_high)


# ──────────────────────────────────────────────
# 9.F. 이중 단계 임계값
# ──────────────────────────────────────────────


class TestGLinerTwoStageThreshold:
    """pre_threshold(1차) + category_thresholds(2차) 동시 적용."""

    def test_predict_entities_called_with_pre_threshold(
        self, tmp_path, monkeypatch
    ):
        # 1차 cut: predict_entities(threshold=0.4) 로 호출됨 (기본)
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-pre-default",
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.65},
            default_threshold=0.5,
            pre_threshold=None,  # spec 에서 생략 → 기본 0.4
            gliner_config_max_types=10,
        )

        adapter.predict("홍길동이 좋아한다")

        # threshold 인자 검증
        call = fake_model.predict_entities.call_args_list[0]
        threshold = call.kwargs.get("threshold")
        if threshold is None and len(call.args) >= 3:
            threshold = call.args[2]
        assert threshold == pytest.approx(0.4)

    def test_pre_threshold_override(self, tmp_path, monkeypatch):
        # spec.pre_threshold = 0.3 으로 명시 → 그 값으로 호출
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-pre-override",
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.65},
            default_threshold=0.5,
            pre_threshold=0.3,
            gliner_config_max_types=10,
        )

        adapter.predict("홍길동이 좋아한다")

        call = fake_model.predict_entities.call_args_list[0]
        threshold = call.kwargs.get("threshold")
        if threshold is None and len(call.args) >= 3:
            threshold = call.args[2]
        assert threshold == pytest.approx(0.3)

    def test_pass_first_pass_second(self, tmp_path, monkeypatch):
        # 1차 통과 + 2차 통과 → 결과에 포함
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-2pass-pass",
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.65},
            default_threshold=0.5,
            pre_threshold=0.3,
            gliner_config_max_types=10,
        )

        # 0.7 — 1차(0.3) 통과, 2차(0.65) 통과
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "홍길동",
                "start": 0,
                "end": 3,
                "score": 0.7,
            }
        ]

        result = adapter.predict("홍길동이 좋다")

        assert any(r.get("entity") == "person" for r in result)

    def test_pass_first_fail_second(self, tmp_path, monkeypatch):
        # 1차 통과 + 2차 실패 → 결과에서 제외
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-2pass-fail",
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.65},
            default_threshold=0.5,
            pre_threshold=0.3,
            gliner_config_max_types=10,
        )

        # 0.5 — 1차(0.3) 통과, 2차(0.65) 실패 → 제거
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "홍길동",
                "start": 0,
                "end": 3,
                "score": 0.5,
            }
        ]

        result = adapter.predict("홍길동이 좋다")

        assert all(r.get("entity") != "person" for r in result)


# ──────────────────────────────────────────────
# 9.G. 후처리 오탐 필터 (한국어 PII 특화)
# ──────────────────────────────────────────────


class TestGLinerPostFilters:
    """후처리 오탐 필터 — 라벨별 정규식과 최소 길이."""

    def _adapter_with_label(
        self,
        tmp_path,
        monkeypatch,
        *,
        ko_label,
        norm_label,
        category_thresholds=None,
    ):
        """단일 라벨 특화 어댑터 헬퍼."""
        return _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name=f"gliner-filter-{norm_label}",
            inference_labels=[ko_label],
            label_map={ko_label: norm_label},
            block_singletons=[norm_label],
            category_thresholds=(
                {norm_label: 0.0}
                if category_thresholds is None
                else category_thresholds
            ),
            default_threshold=0.0,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )

    def test_person_single_char_filtered(self, tmp_path, monkeypatch):
        # PERSON 1글자 ("홍") → 거름
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="사람 이름",
            norm_label="person",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "홍",
                "start": 0,
                "end": 1,
                "score": 0.9,
            }
        ]

        result = adapter.predict("홍이 왔다")

        assert all(r.get("entity") != "person" for r in result)

    def test_person_starting_with_digit_filtered(self, tmp_path, monkeypatch):
        # PERSON 숫자 시작 ("1길동") → 거름
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="사람 이름",
            norm_label="person",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "1길동",
                "start": 0,
                "end": 3,
                "score": 0.95,
            }
        ]

        result = adapter.predict("1길동이 왔다")

        assert all(r.get("entity") != "person" for r in result)

    def test_person_with_josa_trimmed(self, tmp_path, monkeypatch):
        # 조사가 붙은 경우 자동 trim — "정하은이지" → "정하은"
        # word/start/end 가 trim 결과로 보정됨
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="사람 이름",
            norm_label="person",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "정하은이지",
                "start": 5,
                "end": 10,
                "score": 0.95,
            }
        ]

        result = adapter.predict("어제 본 정하은이지 그 사람")

        person_results = [r for r in result if r.get("entity") == "person"]
        assert len(person_results) == 1
        ent = person_results[0]
        assert ent["word"] == "정하은"
        # start 는 그대로, end 는 줄어들어야 한다
        assert ent["start"] == 5
        end = ent.get("end", ent["start"] + len(ent["word"]))
        assert end == 5 + len("정하은")

    def test_person_organization_suffix_filtered(self, tmp_path, monkeypatch):
        # PERSON 으로 잡혔지만 조직 접미사("주식회사") 포함 → 거름
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="사람 이름",
            norm_label="person",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "삼성주식회사",
                "start": 0,
                "end": 6,
                "score": 0.95,
            }
        ]

        result = adapter.predict("삼성주식회사 발표")

        assert all(r.get("entity") != "person" for r in result)

    def test_organization_common_noun_filtered(self, tmp_path, monkeypatch):
        # ORGANIZATION 일반명사 "회사" → 거름
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="기관명",
            norm_label="organization",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "기관명",
                "text": "회사",
                "start": 0,
                "end": 2,
                "score": 0.9,
            }
        ]

        result = adapter.predict("회사 다닌다")

        assert all(r.get("entity") != "organization" for r in result)

    def test_organization_standalone_bank_name_filtered(
        self, tmp_path, monkeypatch
    ):
        # ORGANIZATION 단독 은행명 "우리" → 거름
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="기관명",
            norm_label="organization",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "기관명",
                "text": "우리",
                "start": 0,
                "end": 2,
                "score": 0.9,
            }
        ]

        result = adapter.predict("우리 같이")

        assert all(r.get("entity") != "organization" for r in result)

    def test_address_standalone_place_filtered(self, tmp_path, monkeypatch):
        # ADDRESS 단독 지명 "서울" → 거름 (최소 2개 요소 필요)
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="주소",
            norm_label="address",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "주소",
                "text": "서울",
                "start": 0,
                "end": 2,
                "score": 0.9,
            }
        ]

        result = adapter.predict("서울에 간다")

        assert all(r.get("entity") != "address" for r in result)

    def test_job_title_single_char_filtered(self, tmp_path, monkeypatch):
        # JOB_TITLE 1글자 → 거름
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="직업명",
            norm_label="job_title",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "직업명",
                "text": "장",
                "start": 0,
                "end": 1,
                "score": 0.9,
            }
        ]

        result = adapter.predict("장 직급")

        assert all(r.get("entity") != "job_title" for r in result)

    def test_min_length_person_below_two_filtered(self, tmp_path, monkeypatch):
        # PERSON 최소 길이 2 미만 → 거름 (1글자 정확히 동일 케이스도 보장)
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="사람 이름",
            norm_label="person",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "박",
                "start": 0,
                "end": 1,
                "score": 0.9,
            }
        ]

        result = adapter.predict("박 회의")

        assert all(r.get("entity") != "person" for r in result)

    def test_min_length_address_below_five_filtered(
        self, tmp_path, monkeypatch
    ):
        # ADDRESS 최소 길이 5 미만 → 거름 (조각 주소)
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="주소",
            norm_label="address",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "주소",
                "text": "강남구",
                "start": 0,
                "end": 3,
                "score": 0.9,
            }
        ]

        result = adapter.predict("강남구로")

        assert all(r.get("entity") != "address" for r in result)

    def test_address_full_address_kept(self, tmp_path, monkeypatch):
        # ADDRESS 충분히 긴 (요소 ≥2) 주소는 유지
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="주소",
            norm_label="address",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "주소",
                "text": "서울시 강남구 역삼동 123-45",
                "start": 0,
                "end": 18,
                "score": 0.95,
            }
        ]

        result = adapter.predict("서울시 강남구 역삼동 123-45 거주")

        assert any(r.get("entity") == "address" for r in result)

    def test_person_normal_kept(self, tmp_path, monkeypatch):
        # 정상 PERSON ("홍길동") 은 유지
        adapter, fake_model, _ = self._adapter_with_label(
            tmp_path,
            monkeypatch,
            ko_label="사람 이름",
            norm_label="person",
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "홍길동",
                "start": 0,
                "end": 3,
                "score": 0.9,
            }
        ]

        result = adapter.predict("홍길동이 왔다")

        assert any(r.get("entity") == "person" for r in result)


# ──────────────────────────────────────────────
# 9.H. 출력 정규화 + check_ner 통합
# ──────────────────────────────────────────────


class TestGLinerOutputAndIntegration:
    """predict 출력 키 + L5Layer._check_ner 차단 흐름."""

    def test_predict_output_has_required_keys(self, tmp_path, monkeypatch):
        # entity / word / start / end / score 키가 모두 노출됨
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-out-keys",
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.0},
            default_threshold=0.0,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )
        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "홍길동",
                "start": 0,
                "end": 3,
                "score": 0.9,
            }
        ]

        result = adapter.predict("홍길동이 왔다")

        assert len(result) == 1
        ent = result[0]
        for key in ("entity", "word", "start", "end", "score"):
            assert key in ent

    async def test_gliner_entity_flows_into_check_ner_singleton(
        self, tmp_path, monkeypatch
    ):
        # 어댑터가 반환한 person 엔티티 → L5Layer._check_ner 가
        # singleton 차단으로 처리
        _write_gliner_model_dir(
            tmp_path,
            name="gliner-integ-singleton",
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.0},
            default_threshold=0.0,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_model, _ = _patch_gliner(monkeypatch)
        _patch_pretrained_tokenizer_fast(monkeypatch)

        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "홍길동",
                "start": 0,
                "end": 3,
                "score": 0.9,
            }
        ]

        inst = L5Layer(model_name="gliner-integ-singleton")
        result = await inst.check(_req("홍길동이 왔다"))

        assert result.allowed is False
        assert "person" in result.tags
        assert "ner" in result.tags
        assert "PII detected: person" in result.reason

    async def test_gliner_entity_flows_into_check_ner_combination(
        self, tmp_path, monkeypatch
    ):
        # person + location 동시 감지 → 조합 차단
        _write_gliner_model_dir(
            tmp_path,
            name="gliner-integ-combo",
            inference_labels=["사람 이름", "위치명"],
            label_map={"사람 이름": "person", "위치명": "location"},
            block_singletons=[],
            block_combinations=[["person", "location"]],
            category_thresholds={"person": 0.0, "location": 0.0},
            default_threshold=0.0,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_model, _ = _patch_gliner(monkeypatch)
        _patch_pretrained_tokenizer_fast(monkeypatch)

        fake_model.predict_entities.return_value = [
            {
                "label": "사람 이름",
                "text": "홍길동",
                "start": 0,
                "end": 3,
                "score": 0.9,
            },
            {
                "label": "위치명",
                "text": "서울",
                "start": 5,
                "end": 7,
                "score": 0.9,
            },
        ]

        inst = L5Layer(model_name="gliner-integ-combo")
        result = await inst.check(_req("홍길동이 서울에 산다"))

        assert result.allowed is False
        assert "person" in result.tags
        assert "location" in result.tags
        assert "+" in (result.reason or "")


# ──────────────────────────────────────────────
# 9.I. fail-open 케이스
# ──────────────────────────────────────────────


class TestGLinerFailOpen:
    """GLiNER 어댑터의 fail-open 동작."""

    def test_unknown_adapter_value_fails_open(self, tmp_path, monkeypatch):
        # 알 수 없는 adapter 값 → fail-open
        _write_gliner_model_dir(
            tmp_path,
            name="gliner-unknown",
            adapter="totally-novel-adapter",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        _patch_gliner(monkeypatch)
        _patch_pretrained_tokenizer_fast(monkeypatch)

        inst = L5Layer(model_name="gliner-unknown")

        assert inst._adapter is None
        assert inst._ner_model is None

    def test_predict_entities_exception_window_fail_open(
        self, tmp_path, monkeypatch
    ):
        # predict_entities 가 예외를 던져도 어댑터 predict 는 빈 결과를
        # 반환 (해당 윈도우만 스킵, 전체 fail-open)
        adapter, fake_model, _ = _make_gliner_adapter(
            tmp_path,
            monkeypatch,
            name="gliner-window-fail",
            inference_labels=["사람 이름"],
            label_map={"사람 이름": "person"},
            block_singletons=["person"],
            category_thresholds={"person": 0.0},
            default_threshold=0.0,
            pre_threshold=0.0,
            gliner_config_max_types=10,
        )

        def _boom(*args, **kwargs):
            msg = "GLiNER inference failure"
            raise RuntimeError(msg)

        fake_model.predict_entities.side_effect = _boom

        # 예외 전파 없이 빈 결과
        result = adapter.predict("홍길동이 왔다")
        assert result == []

    async def test_l5_layer_allows_when_gliner_load_failed(
        self, tmp_path, monkeypatch
    ):
        # GLiNER 어댑터 로드 실패 시 L5Layer 는 NER 비활성화로 fail-open
        _write_gliner_model_dir(tmp_path, name="gliner-load-fail")
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)

        import gliner as gliner_pkg

        def _boom(*args, **kwargs):
            msg = "GLiNER load failed"
            raise RuntimeError(msg)

        monkeypatch.setattr(gliner_pkg.GLiNER, "from_pretrained", _boom)
        _patch_pretrained_tokenizer_fast(monkeypatch)

        inst = L5Layer(model_name="gliner-load-fail")
        # NER 전용 입력 (Regex 미매칭) → fail-open 이므로 허용
        result = await inst.check(_req("홍길동이 서울에 산다"))

        assert result.allowed is True
        assert inst._adapter is None
        assert inst._ner_model is None


# ──────────────────────────────────────────────
# 9.J. 회귀 방지 — 기존 hf-pipeline / hf-charlevel 통합
# ──────────────────────────────────────────────


class TestGLinerRegression:
    """GLiNER 추가가 기존 어댑터 dispatch 에 영향을 미치지 않는지."""

    def test_ner_ko_still_dispatches_to_pipeline(self, monkeypatch):
        # 실제 ner-ko 모델 폴더 — 여전히 _HFPipelineAdapter 로 분기
        _patch_pipeline(monkeypatch)

        inst = L5Layer(model_name="ner-ko")

        assert isinstance(inst._adapter, l5_mod._HFPipelineAdapter)

    def test_pii_model_v11_still_dispatches_to_charlevel(
        self, tmp_path, monkeypatch
    ):
        # pii_model_v11 같은 charlevel 어댑터 분기 회귀 없음
        _write_charlevel_model_dir(
            tmp_path,
            name="charlevel-regression",
            adapter="hf-charlevel",
        )
        monkeypatch.setattr(l5_mod, "_MODEL_BASE_DIR", tmp_path)
        _patch_pipeline(monkeypatch)
        fake_tokenizer = MagicMock()
        fake_tokenizer.add_tokens = MagicMock(return_value=1)
        fake_model = MagicMock()
        fake_model.eval = MagicMock(return_value=fake_model)
        fake_model.resize_token_embeddings = MagicMock()
        monkeypatch.setattr(
            l5_mod,
            "AutoTokenizer",
            MagicMock(from_pretrained=MagicMock(return_value=fake_tokenizer)),
            raising=False,
        )
        monkeypatch.setattr(
            l5_mod,
            "AutoModelForTokenClassification",
            MagicMock(from_pretrained=MagicMock(return_value=fake_model)),
            raising=False,
        )

        inst = L5Layer(model_name="charlevel-regression")

        assert isinstance(inst._adapter, l5_mod._HFCharLevelAdapter)
