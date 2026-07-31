"""Two sample stores with different lifetimes.

* :class:`TailBuffer` is in memory, bounded, and non-blocking. It backs the live view.
  If a browser cannot keep up, the browser loses frames (D-37).
* :func:`record_samples` persists a bounded traffic sample to SQLite. The impact preview
  (D-27) and the offline replay (D-29) both read it. The live buffer is far too short-lived
  for either.

Neither ever applies backpressure toward the data plane.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque
from collections.abc import Iterable

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from sixthsense.db.models import SampleEventRow
from sixthsense.models.rule import DecisionRecord


class TailBuffer:
    """A bounded ring buffer with fan-out to live subscribers.

    Publishing never blocks and never raises. A slow subscriber loses messages rather than
    slowing the publisher, because the publisher is on the path from the data plane.
    """

    def __init__(self, maxlen: int = 500) -> None:
        self._items: deque[DecisionRecord] = deque(maxlen=maxlen)
        self._subscribers: set[asyncio.Queue[DecisionRecord]] = set()

    def publish(self, record: DecisionRecord) -> None:
        self._items.append(record)
        for queue in list(self._subscribers):
            # Deliberate: a full subscriber queue drops the frame rather than blocking the
            # publisher, which sits on the path from the data plane. See D-37.
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(record)

    def recent(self, limit: int = 100) -> list[DecisionRecord]:
        items = list(self._items)
        return items[-limit:][::-1]

    def subscribe(self, maxsize: int = 100) -> asyncio.Queue[DecisionRecord]:
        queue: asyncio.Queue[DecisionRecord] = asyncio.Queue(maxsize=maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[DecisionRecord]) -> None:
        self._subscribers.discard(queue)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


_tail = TailBuffer()


def get_tail_buffer() -> TailBuffer:
    return _tail


def record_samples(
    session: Session,
    records: Iterable[DecisionRecord],
    *,
    max_events: int,
    retain_raw: bool,
) -> int:
    """Persist decision samples, trimming the oldest rows past ``max_events``.

    Set ``retain_raw`` to False when events can contain regulated data. The preview then
    works from parsed fields only and is correspondingly less precise, which is the right
    trade when the alternative is writing credentials to disk (D-36).
    """
    count = 0
    for record in records:
        session.add(
            SampleEventRow(
                ts=record.ts,
                decision=record.decision.value,
                rule_id=record.rule_id,
                node=record.node,
                fields=dict(record.fields),
                raw=record.raw if retain_raw else None,
            )
        )
        count += 1

    session.flush()

    total = session.scalar(select(func.count()).select_from(SampleEventRow)) or 0
    if total > max_events:
        excess = total - max_events
        cutoff = session.scalar(
            select(SampleEventRow.id).order_by(SampleEventRow.id).offset(excess - 1).limit(1)
        )
        if cutoff is not None:
            session.execute(delete(SampleEventRow).where(SampleEventRow.id <= cutoff))

    return count


def load_samples(session: Session, *, limit: int = 5000) -> list[SampleEventRow]:
    """Most recent samples first."""
    stmt = select(SampleEventRow).order_by(SampleEventRow.id.desc()).limit(limit)
    return list(session.scalars(stmt))
