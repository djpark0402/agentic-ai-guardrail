"""L4 가드레일 레이어: OWASP 보안 정책 위반 검사.

NLI 선필터 → 벡터 검색 + reranking → LLM 최종 판단의
3단계 파이프라인으로 정책 위반 여부를 판정한다.
"""

import logging
from pathlib import Path
from typing import Any

from core_secure_layer.layers.base import BaseLayer
from core_secure_layer.layers.types import (
    GuardrailRequest,
    LayerResult,
    Severity,
)

try:
    from sentence_transformers import CrossEncoder
except ImportError:  # pragma: no cover
    CrossEncoder = None  # type: ignore[assignment,misc]

try:
    import chromadb
except ImportError:  # pragma: no cover
    chromadb = None  # type: ignore[assignment]

try:
    from langchain_core.language_models import (
        BaseChatModel,
    )
except ImportError:  # pragma: no cover
    BaseChatModel = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

_L4_DIR = Path(__file__).resolve().parent
_MODEL_BASE_DIR = _L4_DIR / "model"


def _allow(name: str = "L4") -> LayerResult:
    """허용 결과를 반환한다.

    Args:
        name: 레이어 이름.

    Returns:
        허용 상태의 LayerResult.
    """
    return LayerResult(
        name=name,
        allowed=True,
        severity=Severity.NONE,
        confidence=1.0,
    )


def _block(
    name: str,
    policy_name: str,
    policy_category: str,
    nli_score: float,
) -> LayerResult:
    """차단 결과를 반환한다.

    Args:
        name: 레이어 이름.
        policy_name: 위반 정책 이름.
        policy_category: 위반 정책 카테고리.
        nli_score: NLI contradiction 점수.

    Returns:
        차단 상태의 LayerResult.
    """
    reason = (
        f'policy violation: "{policy_name}" (nli: {nli_score:.2f}, llm: BLOCK)'
    )
    return LayerResult(
        name=name,
        allowed=False,
        reason=reason,
        severity=Severity.CRITICAL,
        confidence=0.0,
        tags=["policy", "owasp", policy_category],
    )


class L4Layer(BaseLayer):
    """OWASP 보안 정책 위반 여부를 3단계로 검사하는 레이어.

    1단계: NLI 선필터로 의심 여부 빠르게 판단.
    2단계: ChromaDB 벡터 검색 + cross-encoder reranking.
    3단계: LLM 최종 ALLOW/BLOCK 판단.

    모든 단계에서 예외 또는 모델 미로드 시 fail-open(허용).
    """

    name: str = "L4"

    def __init__(
        self,
        nli_model_name: str = "nli_custom_model",
        embed_model_name: str = "Qwen3-Embedding-0.6B",
        reranker_model_name: str = "bge-reranker-v2-m3",
        llm: Any = None,
        nli_threshold: float = 0.7,
        top_k: int = 3,
    ) -> None:
        """L4 레이어를 초기화한다.

        Args:
            nli_model_name: NLI 모델 폴더명.
            embed_model_name: 임베딩 모델 폴더명.
            reranker_model_name: reranker 모델 폴더명.
            llm: LangChain BaseChatModel 인스턴스.
            nli_threshold: NLI contradiction 임계값.
            top_k: 벡터 검색 결과 수.
        """
        self.nli_threshold = nli_threshold
        self.top_k = top_k
        self._llm = llm

        # NLI 모델 로드 시도
        self._nli_model = self._load_cross_encoder("nli", nli_model_name)
        # 임베딩 모델 로드 시도 (SentenceTransformer)
        self._embed_model = self._load_sentence_transformer(
            "embed", embed_model_name
        )
        # Reranker 모델 로드 시도
        self._reranker_model = self._load_cross_encoder(
            "reranker", reranker_model_name
        )
        # ChromaDB 컬렉션 로드 시도
        self._collection = self._load_collection()

    def _load_cross_encoder(
        self,
        category: str,
        model_name: str,
    ) -> Any:
        """cross-encoder 모델을 로드한다.

        Args:
            category: 모델 카테고리 (nli, embed, reranker).
            model_name: 모델 폴더명.

        Returns:
            로드된 모델 또는 None.
        """
        if CrossEncoder is None:
            return None
        model_path = _MODEL_BASE_DIR / category / model_name
        if not model_path.exists():
            return None
        try:
            return CrossEncoder(str(model_path))
        except Exception:
            logger.warning("모델 로드 실패: %s/%s", category, model_name)
            return None

    def _load_sentence_transformer(
        self,
        category: str,
        model_name: str,
    ) -> Any:
        """sentence-transformers 모델을 로드한다.

        Args:
            category: 모델 카테고리.
            model_name: 모델 폴더명.

        Returns:
            로드된 모델 또는 None.
        """
        try:
            from sentence_transformers import (
                SentenceTransformer,
            )
        except ImportError:
            return None
        model_path = _MODEL_BASE_DIR / category / model_name
        if not model_path.exists():
            return None
        try:
            return SentenceTransformer(str(model_path))
        except Exception:
            logger.warning(
                "임베딩 모델 로드 실패: %s/%s",
                category,
                model_name,
            )
            return None

    def _load_collection(self) -> Any:
        """ChromaDB 컬렉션을 로드한다.

        Returns:
            로드된 컬렉션 또는 None.
        """
        if chromadb is None:
            return None
        db_path = _L4_DIR / "vectordb"
        if not db_path.exists():
            return None
        try:
            client = chromadb.PersistentClient(
                path=str(db_path),
            )
            return client.get_collection("policy_chunks")
        except Exception:
            logger.warning("ChromaDB 컬렉션 로드 실패")
            return None

    def _nli_predict(self, text: str) -> float:
        """NLI 모델로 contradiction 점수를 예측한다.

        Args:
            text: 입력 텍스트.

        Returns:
            contradiction 점수 (0.0~1.0).
        """
        import numpy as np

        scores = self._nli_model.predict(
            [(text, "This input violates security policy")]
        )
        # cross-encoder 출력: 2차원 [[ent, neu, con]]
        arr = np.array(scores)
        if arr.ndim == 2:
            # softmax 적용 후 contradiction(인덱스 2) 추출
            exp = np.exp(arr[0] - np.max(arr[0]))
            probs = exp / exp.sum()
            return float(probs[2])
        if arr.ndim == 1 and len(arr) >= 3:
            exp = np.exp(arr - np.max(arr))
            probs = exp / exp.sum()
            return float(probs[2])
        return float(arr.flat[0])

    def _search_policies(self, text: str) -> list[dict[str, str]]:
        """벡터 검색으로 관련 정책 청크를 검색한다.

        Args:
            text: 입력 텍스트.

        Returns:
            정책 청크 딕셔너리 리스트.
        """
        embedding = self._embed_model.encode(text)
        results = self._collection.query(
            query_embeddings=[embedding.tolist()],
            n_results=self.top_k,
        )
        chunks = []
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        for doc, meta in zip(documents, metadatas, strict=False):
            chunks.append(
                {
                    "text": doc,
                    "name": meta.get("name", ""),
                    "category": meta.get("category", ""),
                }
            )
        return chunks

    def _rerank(
        self,
        text: str,
        chunks: list[dict[str, str]],
    ) -> dict[str, str]:
        """cross-encoder로 청크를 재순위화하여 top-1을 반환한다.

        Args:
            text: 입력 텍스트.
            chunks: 정책 청크 리스트.

        Returns:
            최고 점수 청크.
        """
        if self._reranker_model is None:
            msg = "reranker 모델 미로드"
            raise RuntimeError(msg)
        pairs = [(text, c["text"]) for c in chunks]
        scores = self._reranker_model.predict(pairs)
        best_idx = max(range(len(scores)), key=lambda i: scores[i])
        return chunks[best_idx]

    async def _llm_judge(self, text: str, chunk: dict[str, str]) -> str:
        """LLM으로 정책 위반 여부를 최종 판단한다.

        Args:
            text: 입력 텍스트.
            chunk: top-1 정책 청크.

        Returns:
            'ALLOW' 또는 'BLOCK' 문자열.
        """
        prompt = (
            "당신은 보안 정책 준수 여부를 판단하는 심사관입니다.\n\n"
            f"정책:\n{chunk['text']}\n\n"
            f"사용자 입력:\n{text}\n\n"
            "이 입력이 위 정책을 위반하는지 판단하세요.\n"
            "반드시 아래 형식으로만 답하세요:\n"
            "ALLOW 또는 BLOCK"
        )
        response = await self._llm.ainvoke(prompt)
        content = (
            response.content if hasattr(response, "content") else str(response)
        )
        return content.strip().upper()

    async def _check(
        self,
        request: GuardrailRequest,
    ) -> LayerResult:
        """L4 3단계 파이프라인으로 정책 위반 여부를 검사한다.

        Args:
            request: 가드레일 요청 객체.

        Returns:
            레이어의 검사 결과.
        """
        text = request.user_input

        # 빈 문자열은 검사 불필요
        if not text:
            return _allow(self.name)

        # 1단계: NLI 선필터
        if self._nli_model is None:
            return _allow(self.name)

        try:
            nli_score = self._nli_predict(text)
        except Exception:
            logger.warning("NLI 추론 중 예외 발생")
            return _allow(self.name)

        # contradiction > threshold → 의심 없음 → 허용
        if nli_score > self.nli_threshold:
            return _allow(self.name)

        # 2단계: 벡터 검색 + reranking
        if self._embed_model is None or self._collection is None:
            return _allow(self.name)

        try:
            chunks = self._search_policies(text)
        except Exception:
            logger.warning("벡터 검색 중 예외 발생")
            return _allow(self.name)

        if not chunks:
            return _allow(self.name)

        try:
            top_chunk = self._rerank(text, chunks)
        except Exception:
            logger.warning("reranking 중 예외 발생")
            return _allow(self.name)

        # 3단계: LLM 최종 판단
        if self._llm is None:
            return _allow(self.name)

        try:
            verdict = await self._llm_judge(text, top_chunk)
        except Exception:
            logger.warning("LLM 판단 중 예외 발생")
            return _allow(self.name)

        if verdict == "BLOCK":
            return _block(
                name=self.name,
                policy_name=top_chunk["name"],
                policy_category=top_chunk["category"],
                nli_score=nli_score,
            )

        # ALLOW 또는 파싱 불가 응답 → 허용
        return _allow(self.name)
