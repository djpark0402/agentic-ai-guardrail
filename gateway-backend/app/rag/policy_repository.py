from dataclasses import dataclass
from typing import Any

from sqlalchemy import text


@dataclass
class PolicyMatch:
    policy_id: str
    name: str
    distance: float


class PolicyRepository:
    def __init__(self, session: Any):
        self.session = session

    async def search_similar(self, embedding: list[float], top_k: int = 5) -> list[PolicyMatch]:
        sql = text(
            "SELECT policy_id, name, embedding <-> :embedding AS distance "
            "FROM policy ORDER BY embedding <-> :embedding ASC LIMIT :top_k"
        )
        result = self.session.execute(sql, {"embedding": embedding, "top_k": top_k})
        rows = result.fetchall()
        matches = [
            PolicyMatch(policy_id=row[0], name=row[1], distance=float(row[2]))
            for row in rows
        ]
        matches.sort(key=lambda m: m.distance)
        return matches
