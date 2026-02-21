import os
import logging
import threading

import config
from detector.events import EventStore
from detector.analyzer import BehavioralAnalyzer
from detector.shadow import ShadowManager
from detector.response import ResponseHandler
from detector.reporter import IncidentReporter
from detector.watcher import SandboxEventHandler, FileSystemWatcher

logger = logging.getLogger(__name__)


class DetectionDaemon:
    def __init__(self):
        self.event_store = EventStore()
        self.shadow = ShadowManager(config.SANDBOX_DIR, config.SHADOW_DIR)
        self.analyzer = BehavioralAnalyzer(config, self.event_store)
        self.reporter = IncidentReporter(config.REPORT_DIR)
        self.response = ResponseHandler(
            config, self.event_store, self.shadow, self.reporter
        )
        self.watcher = None
        self.running = False
        self._response_thread = None

    def _on_threat_detected(self, threat_summary):
        self.event_store.add_event(
            "THREAT_CONFIRMED",
            "critical",
            f"Ransomware behavior confirmed — threat score: {threat_summary['score']}. "
            f"Engaging automated response.",
            threat_summary,
        )

        self._response_thread = threading.Thread(
            target=self.response.execute_response,
            args=(config.SANDBOX_DIR, threat_summary),
        )
        self._response_thread.start()

    def start(self):
        self.event_store.add_event(
            "DAEMON_START", "info", "Detection daemon initializing..."
        )

        if not os.path.exists(config.SANDBOX_DIR):
            self.event_store.add_event(
                "ERROR",
                "high",
                f"Sandbox directory not found: {config.SANDBOX_DIR}",
            )
            return False

        file_count = self.shadow.create_snapshot()
        self.event_store.add_event(
            "SHADOW_SNAPSHOT",
            "info",
            f"Shadow snapshot created — {file_count} files backed up to {config.SHADOW_DIR}",
        )

        self.analyzer.build_baseline(config.SANDBOX_DIR)

        handler = SandboxEventHandler(
            self.analyzer,
            self.response,
            config.SANDBOX_DIR,
            self._on_threat_detected,
        )

        self.watcher = FileSystemWatcher(config.SANDBOX_DIR, handler)
        self.watcher.start()
        self.running = True

        self.event_store.add_event(
            "MONITORING_ACTIVE",
            "info",
            f"Real-time filesystem monitoring active on {config.SANDBOX_DIR}",
        )

        logger.info("Detection daemon started")
        return True

    def stop(self):
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        self.running = False
        if self._response_thread and self._response_thread.is_alive():
            self._response_thread.join(timeout=10)
        self.event_store.add_event(
            "DAEMON_STOP", "info", "Detection daemon stopped."
        )
        logger.info("Detection daemon stopped")

    def reset(self):
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        self.running = False
        self.analyzer.reset()
        self.event_store.reset()
        logger.info("Daemon state reset")

    def is_running(self):
        return self.running and self.watcher and self.watcher.is_alive()
