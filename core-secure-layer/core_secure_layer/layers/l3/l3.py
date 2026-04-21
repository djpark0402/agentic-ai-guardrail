"""L3 가드레일 레이어 — 공격 패턴 유사도 기반 차단."""

import logging
import pathlib
from typing import Any

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

logger = logging.getLogger(__name__)

_L3_DIR: pathlib.Path = pathlib.Path(__file__).resolve().parent
_DEFAULT_DB_PATH: str = str(_L3_DIR / "vectordb")
_MODEL_BASE_DIR: pathlib.Path = _L3_DIR / "model"
_DEFAULT_MODEL_NAME: str = "all-MiniLM-L6-v2"


class L3Layer(BaseLayer):
    """VectorDB 임베딩 유사도 기반 공격 패턴 탐지 레이어.

    사용자 입력을 임베딩하여 ChromaDB에 저장된 공격 패턴과
    코사인 유사도를 비교한다. top-K 결과의 평균 유사도가
    임계값을 초과하면 차단한다.
    """

    name: str = "L3"

    def __init__(
        self,
        db_path: str = _DEFAULT_DB_PATH,
        model_name: str = _DEFAULT_MODEL_NAME,
        similarity_threshold: float = 0.8,
        top_k: int = 5,
    ) -> None:
        """L3 레이어를 초기화한다.

        Args:
            db_path: ChromaDB 영속 저장 경로.
            model_name: 임베딩 모델 폴더명 (예:
                ``"all-MiniLM-L6-v2"``).
            similarity_threshold: 평균 유사도 차단 임계값.
            top_k: 검색할 유사 패턴 수.
        """
        self.db_path = db_path
        self.model_path = str(
            _MODEL_BASE_DIR / model_name,
        )
        self.similarity_threshold = similarity_threshold
        self.top_k = top_k
        self._model: Any = None
        self._collection: Any = None
        self._db_loaded = False
        self._model_loaded = False
        self._load_resources()

    def _load_resources(self) -> None:
        """임베딩 모델과 ChromaDB를 로드한다.

        로드 실패 시 경고만 남기고 fail-open 으로 동작한다.
        """
        try:
            from sentence_transformers import (  # type: ignore[import-untyped]
                SentenceTransformer,
            )

            self._model = SentenceTransformer(self.model_path)
            self._model_loaded = True
        except Exception:
            logger.warning(
                "임베딩 모델 로드 실패: %s",
                self.model_path,
            )
            self._model_loaded = False

        try:
            import chromadb  # type: ignore[import-untyped]

            client = chromadb.PersistentClient(
                path=self.db_path,
            )
            self._collection = client.get_or_create_collection(
                name="attack_patterns",
            )
            self._db_loaded = True
        except Exception:
            logger.warning(
                "ChromaDB 로드 실패: %s",
                self.db_path,
            )
            self._db_loaded = False

    def _embed(self, text: str) -> list[float]:
        """텍스트를 벡터로 임베딩한다.

        Args:
            text: 임베딩할 텍스트.

        Returns:
            임베딩 벡터 리스트.
        """
        return self._model.encode(text).tolist()

    def _search_similar(
        self,
        text: str,
    ) -> list[dict[str, Any]]:
        """ChromaDB에서 유사 공격 패턴을 검색한다.

        Args:
            text: 검색 대상 텍스트.

        Returns:
            유사도와 패턴 이름이 포함된 결과 리스트.
            각 항목은 ``{"name": str, "similarity": float}``
            형태이다.
        """
        embedding = self._embed(text)
        results = self._collection.query(
            query_embeddings=[embedding],
            n_results=self.top_k,
        )
        items: list[dict[str, Any]] = []
        if not results or not results.get("ids"):
            return items
        ids = results["ids"][0]
        distances = results["distances"][0]
        metadatas = results.get("metadatas", [[]])[0]
        for i, doc_id in enumerate(ids):
            name = (
                metadatas[i].get("name", doc_id)
                if metadatas and i < len(metadatas)
                else doc_id
            )
            similarity = 1.0 - distances[i]
            items.append(
                {"name": name, "similarity": similarity},
            )
        return items

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """L3 검사를 실행한다.

        사용자 입력을 임베딩하여 공격 패턴 DB와
        유사도를 비교하고, 임계값 초과 시 차단한다.

        Args:
            request: 가드레일 요청 객체.

        Returns:
            레이어의 검사 결과.
        """
        try:
            return self._inspect(request.user_input)
        except Exception:
            logger.warning("L3 검사 중 예외 발생 — fail-open 허용")
            return self._allow()

    def _inspect(self, text: str) -> LayerResult:
        """입력 텍스트를 검사한다.

        Args:
            text: 검사할 원본 입력 문자열.

        Returns:
            검사 결과 LayerResult.
        """
        # 빈 문자열 → 즉시 허용
        if not text:
            return self._allow()

        # 모델/DB 미로드 → fail-open
        if not getattr(self, "_model_loaded", False):
            return self._allow()
        if not getattr(self, "_db_loaded", False):
            return self._allow()

        results = self._search_similar(text)

        # 검색 결과 없음 → 허용
        if not results:
            return self._allow()

        top = max(results, key=lambda r: r["similarity"])
        top_sim = top["similarity"]

        if top_sim > self.similarity_threshold:
            pattern_name = top["name"]
            reason = (
                f"similar to attack pattern "
                f'"{pattern_name}" '
                f"(similarity: {top_sim:.2f})"
            )
            return LayerResult(
                name=self.name,
                allowed=False,
                reason=reason,
                severity=Severity.HIGH,
                confidence=0.0,
                tags=["signature", pattern_name],
            )

        return self._allow()

    def _allow(self) -> LayerResult:
        """허용 결과를 생성한다.

        Returns:
            허용 상태의 LayerResult.
        """
        return LayerResult(
            name=self.name,
            allowed=True,
            confidence=1.0,
            severity=Severity.NONE,
        )
