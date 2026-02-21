import os
import logging
import threading

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

RANSOM_SIZE_LIMIT = 102400


class SandboxEventHandler(FileSystemEventHandler):
    def __init__(self, analyzer, response_handler, target_dir, on_threat_callback):
        super().__init__()
        self.analyzer = analyzer
        self.response = response_handler
        self.target_dir = target_dir
        self.on_threat = on_threat_callback
        self._responded = False
        self._lock = threading.Lock()

    def on_modified(self, event):
        if event.is_directory:
            return

        self.analyzer.record_write(event.src_path)
        self.analyzer.analyze_entropy(event.src_path)
        self._check_ransom_note(event.src_path)
        self._evaluate_threat()

    def on_created(self, event):
        if event.is_directory:
            return

        self.analyzer.record_write(event.src_path)
        self.analyzer.analyze_entropy(event.src_path)
        self._check_ransom_note(event.src_path)
        self._evaluate_threat()

    def on_moved(self, event):
        if event.is_directory:
            return

        self.analyzer.record_rename(event.src_path, event.dest_path)

        if os.path.exists(event.dest_path):
            self.analyzer.analyze_entropy(event.dest_path)

        self._evaluate_threat()

    def on_deleted(self, event):
        if event.is_directory:
            return

        self.analyzer.event_store.add_event(
            "FILE_DELETED",
            "medium",
            f"File deleted: {os.path.basename(event.src_path)}",
            {"path": event.src_path},
        )
        self._evaluate_threat()

    def _check_ransom_note(self, filepath):
        try:
            size = os.path.getsize(filepath)
        except OSError:
            return
        if size > RANSOM_SIZE_LIMIT:
            return
        self.analyzer.check_ransom_note(filepath)

    def _evaluate_threat(self):
        if self._responded:
            return

        if self.analyzer.should_trigger_response():
            with self._lock:
                if self._responded:
                    return
                self._responded = True

            self.on_threat(self.analyzer.get_threat_summary())


class FileSystemWatcher:
    def __init__(self, target_dir, handler):
        self.target_dir = target_dir
        self.handler = handler
        self.observer = Observer()

    def start(self):
        self.observer.schedule(self.handler, self.target_dir, recursive=False)
        self.observer.start()
        logger.info("Filesystem watcher started on %s", self.target_dir)

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=5)
        logger.info("Filesystem watcher stopped")

    def is_alive(self):
        return self.observer.is_alive()
