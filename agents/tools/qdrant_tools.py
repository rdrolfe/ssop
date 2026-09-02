"""Qdrant vector memory tool module for infra-agent (LTM/STM).

Hygiene: config-driven (config.py), imports at top, logging, structured errors.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from config import settings

logger = logging.getLogger(__name__)

DEFAULT_VECTOR_SIZE = 384

# Connection-level errors worth retrying (transient network/refusal blips).
# Imported lazily — the qdrant client pulls httpx, but keep the import local
# so this module stays importable even if the transport layer changes.
def _is_transient_error(exc: Exception) -> bool:
    import httpx

    from qdrant_client.http.exceptions import ResponseHandlingException

    return isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                            httpx.ReadError, httpx.RemoteProtocolError, ConnectionError,
                            TimeoutError, OSError, ResponseHandlingException))


def _retry_call(fn, *args, attempts: int = 3, base_delay: float = 0.4, **kwargs):
    """Call fn with bounded retry on transient connection errors.

    Non-transient errors propagate immediately; transient errors retry with
    exponential backoff. Used on every Qdrant write so a brief refusal cannot
    silently drop a point (the JSONL receipt is truth, but the working store
    must not fall behind).
    """
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 — classified below
            if not _is_transient_error(e) or attempt == attempts - 1:
                raise
            last_exc = e
            delay = base_delay * (2 ** attempt)
            logger.warning("qdrant transient failure (attempt %d/%d), retrying in %.1fs: %s",
                           attempt + 1, attempts, delay, e)
            time.sleep(delay)
    raise RuntimeError(f"qdrant transient failure after {attempts} attempts: {last_exc}")


class QdrantError(RuntimeError):
    """Raised when Qdrant is unreachable or an operation fails."""


class QdrantMemory:
    """Long-term and short-term memory backed by Qdrant vector store."""

    def __init__(self, url: str | None = None) -> None:
        # Prefer QDRANT_URL (full URL convention); fall back to host/port.
        self.url = url or settings.qdrant_url or f"http://{settings.qdrant_host}:{settings.qdrant_port}"
        try:
            # Explicit connect/read timeouts so a hung connection cannot block
            # a role forever (no timeout = wait indefinitely on a dead peer).
            self.client = QdrantClient(url=self.url, prefer_grpc=False, timeout=5.0)
        except Exception as e:
            logger.error("qdrant connect failed: %s", e)
            raise QdrantError(f"qdrant connect failed: {e}") from e

    def ensure_collection(self, name: str, vector_size: int = DEFAULT_VECTOR_SIZE) -> dict[str, Any]:
        """Create a collection if it does not exist."""
        try:
            collections = _retry_call(self.client.get_collections).collections
            existing = [c.name for c in collections]
            if name not in existing:
                self.client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
                )
                logger.info("created qdrant collection %s", name)
                return {"created": True, "collection": name}
            return {"created": False, "collection": name}
        except Exception as e:
            logger.error("ensure_collection failed for %s: %s", name, e)
            raise QdrantError(f"ensure_collection failed: {e}") from e

    def store_memory(
        self,
        collection: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        vector: list[float] | None = None,
    ) -> dict[str, Any]:
        """Store a memory entry (decision, observation, state) in Qdrant."""
        self.ensure_collection(collection)
        point_id = str(uuid.uuid4())
        payload: dict[str, Any] = {
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": "infra-agent",
        }
        if metadata:
            payload.update(metadata)
        vec = vector or [0.0] * DEFAULT_VECTOR_SIZE
        try:
            _retry_call(
                self.client.upsert,
                collection_name=collection,
                points=[PointStruct(id=point_id, vector=vec, payload=payload)],
            )
        except Exception as e:
            logger.error("store_memory failed in %s: %s", collection, e)
            raise QdrantError(f"store_memory failed: {e}") from e
        return {"stored": True, "point_id": point_id, "collection": collection}

    def search_memory(self, collection: str, query: str, limit: int = 5,
                      scroll_limit: int = 1000) -> list[dict[str, Any]]:
        """Search memory entries by text content.

        scroll_limit caps how many records the SCROLL pulls before the
        substring filter — callers that need the whole store (recidivism
        scans) must raise it: the default 1000 silently drops the freshest
        cases once the store exceeds 1000 points (the BOTS replay pushed it
        to 1176, breaking entity/host recidivism seeding).
        """
        self.ensure_collection(collection)
        try:
            records = _retry_call(
                self.client.scroll,
                collection_name=collection,
                limit=scroll_limit,
                with_payload=True,
                with_vectors=False,
            )[0]
        except Exception as e:
            logger.error("search_memory scroll failed in %s: %s", collection, e)
            raise QdrantError(f"search_memory failed: {e}") from e

        results: list[dict[str, Any]] = []
        for rec in records:
            payload = rec.payload or {}
            results.append({
                "id": rec.id,
                "content": payload.get("content", ""),
                "timestamp": payload.get("timestamp", ""),
                "agent": payload.get("agent", ""),
                "metadata": {k: v for k, v in payload.items() if k not in ("content", "timestamp", "agent")},
            })

        # Filter by query text (substring — deterministic, no embeddings needed)
        if query:
            q = query.lower()
            results = [r for r in results if q in r["content"].lower()]

        return results[:limit]

    def recent_memories(self, collection: str, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most recent memories by timestamp (descending)."""
        self.ensure_collection(collection)
        try:
            records = _retry_call(
                self.client.scroll,
                collection_name=collection,
                limit=1000,
                with_payload=True,
                with_vectors=False,
            )[0]
        except Exception as e:
            logger.error("recent_memories scroll failed in %s: %s", collection, e)
            raise QdrantError(f"recent_memories failed: {e}") from e

        results: list[dict[str, Any]] = []
        for rec in records:
            payload = rec.payload or {}
            results.append({
                "id": rec.id,
                "content": payload.get("content", ""),
                "timestamp": payload.get("timestamp", ""),
                "agent": payload.get("agent", ""),
                "metadata": {k: v for k, v in payload.items() if k not in ("content", "timestamp", "agent")},
            })
        results.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
        return results[:limit]

    def delete_memory(self, collection: str, point_id: str) -> dict[str, Any]:
        """Delete a memory entry by point id."""
        try:
            _retry_call(self.client.delete, collection_name=collection, points_selector=[point_id])
            return {"deleted": True, "point_id": point_id}
        except Exception as e:
            logger.error("delete_memory failed in %s: %s", collection, e)
            raise QdrantError(f"delete_memory failed: {e}") from e
