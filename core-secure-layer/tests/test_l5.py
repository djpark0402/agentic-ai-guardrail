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
