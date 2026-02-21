import logging
import threading
from collections import deque
from datetime import datetime

logger = logging.getLogger(__name__)


class Event:
    def __init__(self, event_type, severity, description, metadata=None):
        now = datetime.now()
        self.timestamp = now.isoformat()
        self.unix_ts = now.timestamp()
        self.event_type = event_type
        self.severity = severity
        self.description = description
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "unix_ts": self.unix_ts,
            "type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "metadata": self.metadata,
        }


class EventStore:
    def __init__(self, max_events=2000):
        self.events = deque(maxlen=max_events)
        self.kill_decisions = []
        self.process_tree = {}
        self._lock = threading.Lock()
        self._subscribers = []

    def add_event(self, event_type, severity, description, metadata=None):
        event = Event(event_type, severity, description, metadata)
        with self._lock:
            self.events.append(event)
        for callback in self._subscribers:
            try:
                callback(event)
            except Exception as e:
                logger.debug("Subscriber callback failed: %s", e)
        return event

    def add_kill_decision(self, pid, process_name, reason, action_taken):
        decision = {
            "timestamp": datetime.now().isoformat(),
            "pid": pid,
            "process_name": process_name,
            "reason": reason,
            "action": action_taken,
        }
        with self._lock:
            self.kill_decisions.append(decision)

        self.add_event(
            "KILL_DECISION",
            "critical",
            f"Process {process_name} (PID {pid}) — {action_taken}: {reason}",
            decision,
        )

    def update_process_tree(self, tree):
        with self._lock:
            self.process_tree = tree

    def subscribe(self, callback):
        with self._lock:
            self._subscribers.append(callback)

    def get_all(self):
        with self._lock:
            return {
                "events": [e.to_dict() for e in self.events],
                "kill_decisions": list(self.kill_decisions),
                "process_tree": dict(self.process_tree),
            }

    def get_recent(self, count=50):
        with self._lock:
            recent = list(self.events)[-count:]
            return [e.to_dict() for e in recent]

    def get_events_since(self, unix_ts):
        with self._lock:
            return [e.to_dict() for e in self.events if e.unix_ts > unix_ts]

    def reset(self):
        with self._lock:
            self.events.clear()
            self.kill_decisions.clear()
            self.process_tree.clear()
        logger.info("Event store reset")
