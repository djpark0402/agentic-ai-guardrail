import pytest

from app.rag.policy_repository import PolicyRepository


@pytest.mark.asyncio
async def test_policy_lookup_by_vector(mocker):
    mock_session = mocker.MagicMock()
    mock_session.execute.return_value.fetchall.return_value = [
        ("pol-1", "block-secrets", 0.12),
        ("pol-2", "block-pii", 0.25),
    ]
    repo = PolicyRepository(session=mock_session)
    results = await repo.search_similar(embedding=[0.1] * 1536, top_k=2)
    assert len(results) == 2
    assert results[0].policy_id == "pol-1"
    assert results[0].distance <= results[1].distance


@pytest.mark.asyncio
async def test_policy_lookup_empty(mocker):
    mock_session = mocker.MagicMock()
    mock_session.execute.return_value.fetchall.return_value = []
    repo = PolicyRepository(session=mock_session)
    results = await repo.search_similar(embedding=[0.0] * 1536, top_k=5)
    assert results == []


@pytest.mark.asyncio
async def test_policy_repository_uses_pgvector_query(mocker):
    mock_session = mocker.MagicMock()
    mock_session.execute.return_value.fetchall.return_value = []
    repo = PolicyRepository(session=mock_session)
    await repo.search_similar(embedding=[0.1] * 1536, top_k=3)
    args, _ = mock_session.execute.call_args
    sql_text = str(args[0])
    assert "policy" in sql_text.lower()
    assert "<->" in sql_text or "embedding" in sql_text.lower()
