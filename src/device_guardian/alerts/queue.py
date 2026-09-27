"""Bounded alert queue with auditable backpressure and priority preservation (Phase 14).

Ensures memory consumption remains strictly bounded under alert storms or slow consumers.
Adheres strictly to the Device Guardian security policy:
- Bounded maximum queue size (default: 100 items).
- Never silently discards security alerts: drops are logged and tracked in reliability metrics.
- Prioritizes higher-severity security alerts over informational notifications under pressure.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
import time
from typing import Any, Generic, Optional, TypeVar

from device_guardian.logger import get_logger
from device_guardian.reliability.metrics import get_reliability_metrics

logger = get_logger("alerts.queue")

T = TypeVar("T")


@dataclass(order=True)
class PrioritizedAlertItem(Generic[T]):
    """Wrapper holding an alert item with its dispatch priority."""

    # Lower integer = higher urgency (e.g. 0=CRITICAL, 1=HIGH, 2=STANDARD, 3=LOW)
    priority: int
    timestamp: float = field(compare=False, default_factory=time.time)
    item: T = field(compare=False, default=None)  # type: ignore


class BoundedAlertQueue(Generic[T]):
    """Thread-safe bounded queue for alert events with explicit backpressure policies."""

    def __init__(self, maxsize: int = 100) -> None:
        """Initialize the bounded alert queue.

        Args:
            maxsize: Maximum number of pending alerts before backpressure engages.
        """
        if maxsize < 1:
            raise ValueError(f"maxsize must be at least 1, got {maxsize}")
        self.maxsize = maxsize
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._not_full = threading.Condition(self._lock)
        self._queue: deque[PrioritizedAlertItem[T]] = deque()
        self._closed = False
        self._dropped_count = 0
        self._metrics = get_reliability_metrics()

    @property
    def is_closed(self) -> bool:
        """Check whether the queue is closed."""
        with self._lock:
            return self._closed

    def qsize(self) -> int:
        """Return the current number of items in the queue."""
        with self._lock:
            return len(self._queue)

    def is_empty(self) -> bool:
        """Return True if the queue is empty."""
        with self._lock:
            return len(self._queue) == 0

    def is_full(self) -> bool:
        """Return True if the queue is at maximum capacity."""
        with self._lock:
            return len(self._queue) >= self.maxsize

    def push(
        self,
        item: T,
        priority: int = 2,
        timeout: Optional[float] = None,
    ) -> bool:
        """Enqueue an alert item with backpressure handling.

        Backpressure Policy:
        1. If space is available, item is enqueued immediately.
        2. If full and timeout is specified, waits up to timeout for space.
        3. If still full:
           - If item has higher priority (lower value) than the lowest-priority
             item in the queue, evicts the lowest-priority item to make room.
           - Otherwise, rejects the incoming item.
           - Every drop/eviction is audited to logs and recorded in reliability metrics.

        Args:
            item: Alert item or event to queue.
            priority: Urgency tier (0=Critical, 1=High, 2=Standard, 3=Low).
            timeout: Optional seconds to wait for space before applying drop policy.

        Returns:
            True if item was successfully enqueued; False if rejected under backpressure.
        """
        alert_entry = PrioritizedAlertItem(priority=priority, item=item)

        with self._not_full:
            if self._closed:
                logger.warning("Attempted to push alert into closed queue. Rejected.")
                return False

            # Wait for space if timeout provided
            if len(self._queue) >= self.maxsize and timeout is not None and timeout > 0:
                end_time = time.time() + timeout
                while len(self._queue) >= self.maxsize and not self._closed:
                    remaining = end_time - time.time()
                    if remaining <= 0:
                        break
                    self._not_full.wait(remaining)

            if self._closed:
                return False

            if len(self._queue) < self.maxsize:
                self._queue.append(alert_entry)
                self._metrics.update_queue_depth(len(self._queue))
                self._not_empty.notify()
                return True

            # Queue remains full: Auditable backpressure resolution
            self._dropped_count += 1
            self._metrics.record_queue_drop()

            # Inspect lowest priority item currently in queue
            max_prio_entry = max(self._queue, key=lambda e: e.priority)
            if alert_entry.priority < max_prio_entry.priority:
                # Evict the lower-priority item to admit this critical alert
                self._queue.remove(max_prio_entry)
                self._queue.append(alert_entry)
                logger.warning(
                    "Alert queue full (%d items). Evicted lower-priority alert (Priority %d) "
                    "to admit high-priority alert (Priority %d). Total dropped: %d.",
                    self.maxsize,
                    max_prio_entry.priority,
                    alert_entry.priority,
                    self._dropped_count,
                )
                self._metrics.update_queue_depth(len(self._queue))
                self._not_empty.notify()
                return True
            else:
                logger.warning(
                    "Alert queue full (%d items). Dropped alert (Priority %d) under backpressure. "
                    "Total dropped: %d.",
                    self.maxsize,
                    alert_entry.priority,
                    self._dropped_count,
                )
                return False

    def pop(self, timeout: Optional[float] = None) -> Optional[T]:
        """Dequeue the highest priority alert item, waiting if necessary.

        Args:
            timeout: Seconds to wait for an item before returning None.

        Returns:
            The alert item if available, or None on timeout or queue closure.
        """
        with self._not_empty:
            if timeout is not None and timeout > 0:
                end_time = time.time() + timeout
                while len(self._queue) == 0 and not self._closed:
                    remaining = end_time - time.time()
                    if remaining <= 0:
                        break
                    self._not_empty.wait(remaining)
            elif timeout is None:
                while len(self._queue) == 0 and not self._closed:
                    self._not_empty.wait()

            if len(self._queue) == 0:
                return None

            # Sort or extract best priority
            # For simplicity with bounded maxsize (e.g. <= 100), find minimum priority index
            best_idx = 0
            best_entry = self._queue[0]
            for idx, entry in enumerate(self._queue):
                if entry.priority < best_entry.priority:
                    best_entry = entry
                    best_idx = idx

            del self._queue[best_idx]
            self._metrics.update_queue_depth(len(self._queue))
            self._not_full.notify()
            return best_entry.item

    def close(self) -> None:
        """Close the queue, unblocking all waiting producers and consumers."""
        with self._lock:
            self._closed = True
            self._not_empty.notify_all()
            self._not_full.notify_all()
            logger.debug("Alert queue closed.")

    def clear(self) -> None:
        """Clear all pending items from the queue."""
        with self._lock:
            self._queue.clear()
            self._metrics.update_queue_depth(0)
            self._not_full.notify_all()
