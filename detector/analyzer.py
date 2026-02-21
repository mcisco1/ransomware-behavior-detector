import os
import time
import logging
import threading
from collections import deque

from utils import shannon_entropy

logger = logging.getLogger(__name__)

RANSOM_SIZE_LIMIT = 102400


class BehavioralAnalyzer:
    def __init__(self, cfg, event_store):
        self.cfg = cfg
        self.event_store = event_store
        self._lock = threading.Lock()

        self.encrypted_rename_timestamps = deque()
        self.rename_timestamps = deque()
        self.write_timestamps = deque()
        self.entropy_spike_timestamps = deque()
        self.ransom_note_timestamps = deque()
        self.yara_match_timestamps = deque()

        self.entropy_baseline = {}

        try:
            from detector.yara_scanner import YaraScanner
            self.yara_scanner = YaraScanner(cfg.YARA_RULES_DIR)
            if self.yara_scanner.available:
                logger.info("YARA scanner loaded with %d rules", self.yara_scanner.rule_count)
            else:
                self.yara_scanner = None
        except Exception:
            self.yara_scanner = None

    def _prune_window(self, event_deque, window_seconds):
        cutoff = time.time() - window_seconds
        while event_deque and event_deque[0] < cutoff:
            event_deque.popleft()

    def _prune_all(self):
        w = self.cfg.DETECTION_WINDOW
        self._prune_window(self.encrypted_rename_timestamps, w)
        self._prune_window(self.rename_timestamps, w)
        self._prune_window(self.write_timestamps, w)
        self._prune_window(self.entropy_spike_timestamps, w)
        self._prune_window(self.ransom_note_timestamps, w)
        self._prune_window(self.yara_match_timestamps, w)

    def compute_threat_score(self):
        with self._lock:
            self._prune_all()
            weights = self.cfg.SIGNAL_WEIGHTS
            window = self.cfg.DETECTION_WINDOW
            score = 0
            reasons = []

            if self.encrypted_rename_timestamps:
                score += weights["encrypted_rename"]
                reasons.append(
                    f"{len(self.encrypted_rename_timestamps)} file(s) renamed "
                    f"with encrypted extension in last {window}s"
                )

            rename_rate = len(self.rename_timestamps) / window if window else 0
            if rename_rate >= self.cfg.RENAME_RATE_THRESHOLD:
                score += weights["rapid_rename_rate"]
                reasons.append(
                    f"Rapid file rename rate: {rename_rate:.1f}/sec "
                    f"(threshold: {self.cfg.RENAME_RATE_THRESHOLD})"
                )

            write_rate = len(self.write_timestamps) / window if window else 0
            if write_rate >= self.cfg.WRITE_VOLUME_THRESHOLD:
                score += weights["high_write_volume"]
                reasons.append(
                    f"Abnormal write volume: {write_rate:.1f}/sec "
                    f"(threshold: {self.cfg.WRITE_VOLUME_THRESHOLD})"
                )

            if self.entropy_spike_timestamps:
                score += weights["entropy_spike"]
                reasons.append(
                    f"{len(self.entropy_spike_timestamps)} entropy spike(s) detected"
                )

            if self.ransom_note_timestamps:
                score += weights["ransom_note"]
                reasons.append("Ransom note content detected")

            if self.yara_match_timestamps:
                score += weights["yara_match"]
                reasons.append("YARA rule matched on scanned file")

            return score, reasons

    def record_rename(self, src_path, dest_path):
        now = time.time()
        with self._lock:
            self.rename_timestamps.append(now)

            if dest_path.endswith(self.cfg.ENCRYPTED_EXTENSION):
                self.encrypted_rename_timestamps.append(now)
                self.event_store.add_event(
                    "RENAME_ENCRYPTED",
                    "high",
                    f"File renamed with encrypted extension: {os.path.basename(dest_path)}",
                    {"source": src_path, "destination": dest_path},
                )

            self._prune_window(self.rename_timestamps, self.cfg.DETECTION_WINDOW)
            rate = len(self.rename_timestamps) / self.cfg.DETECTION_WINDOW
            if rate >= self.cfg.RENAME_RATE_THRESHOLD:
                self.event_store.add_event(
                    "RAPID_RENAME",
                    "critical",
                    f"Rapid file rename rate: {rate:.1f}/sec (threshold: {self.cfg.RENAME_RATE_THRESHOLD})",
                    {"rate": rate, "window": self.cfg.DETECTION_WINDOW},
                )

        logger.debug("Rename recorded: %s -> %s", src_path, dest_path)

    def record_write(self, filepath):
        now = time.time()
        with self._lock:
            self.write_timestamps.append(now)
            self._prune_window(self.write_timestamps, self.cfg.DETECTION_WINDOW)
            rate = len(self.write_timestamps) / self.cfg.DETECTION_WINDOW
            if rate >= self.cfg.WRITE_VOLUME_THRESHOLD:
                self.event_store.add_event(
                    "HIGH_WRITE_VOLUME",
                    "high",
                    f"Abnormal write volume: {rate:.1f}/sec (threshold: {self.cfg.WRITE_VOLUME_THRESHOLD})",
                    {"rate": rate},
                )

    def analyze_entropy(self, filepath):
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except OSError:
            return

        current_entropy = shannon_entropy(data)
        basename = os.path.basename(filepath)

        with self._lock:
            if basename in self.entropy_baseline:
                previous = self.entropy_baseline[basename]
                jump = current_entropy - previous

                if jump >= self.cfg.ENTROPY_JUMP_THRESHOLD:
                    self.entropy_spike_timestamps.append(time.time())
                    self.event_store.add_event(
                        "ENTROPY_SPIKE",
                        "critical",
                        f"Entropy spike on {basename}: {previous:.2f} -> {current_entropy:.2f} (delta: {jump:.2f})",
                        {
                            "file": basename,
                            "previous": round(previous, 4),
                            "current": round(current_entropy, 4),
                            "jump": round(jump, 4),
                        },
                    )

            if current_entropy >= self.cfg.HIGH_ENTROPY_THRESHOLD:
                self.event_store.add_event(
                    "HIGH_ENTROPY",
                    "medium",
                    f"High entropy detected in {basename}: {current_entropy:.2f}",
                    {"file": basename, "entropy": round(current_entropy, 4)},
                )

            self.entropy_baseline[basename] = current_entropy

    def check_ransom_note(self, filepath):
        try:
            size = os.path.getsize(filepath)
        except OSError:
            return False
        if size > RANSOM_SIZE_LIMIT:
            return False

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(8192).lower()
        except OSError:
            return False

        matches = [kw for kw in self.cfg.RANSOM_NOTE_KEYWORDS if kw in content]

        if len(matches) >= 3:
            with self._lock:
                self.ransom_note_timestamps.append(time.time())
                self.event_store.add_event(
                    "RANSOM_NOTE",
                    "critical",
                    f"Ransom note detected: {os.path.basename(filepath)} "
                    f"(keywords: {', '.join(matches[:6])})",
                    {"file": filepath, "keyword_matches": matches},
                )
            logger.warning("Ransom note detected: %s", filepath)
            return True

        if self.yara_scanner:
            try:
                yara_matches = self.yara_scanner.scan_file(filepath)
                if yara_matches:
                    with self._lock:
                        self.yara_match_timestamps.append(time.time())
                        self.event_store.add_event(
                            "YARA_MATCH",
                            "critical",
                            f"YARA rule matched: {os.path.basename(filepath)} "
                            f"({', '.join(str(m) for m in yara_matches)})",
                            {"file": filepath, "rules": [str(m) for m in yara_matches]},
                        )
                    return True
            except Exception:
                pass

        return False

    def build_baseline(self, directory):
        for entry in os.scandir(directory):
            if entry.is_file():
                try:
                    with open(entry.path, "rb") as f:
                        data = f.read()
                    self.entropy_baseline[entry.name] = shannon_entropy(data)
                except OSError:
                    pass

        self.event_store.add_event(
            "BASELINE",
            "info",
            f"Entropy baseline established for {len(self.entropy_baseline)} files",
        )
        logger.info("Entropy baseline: %d files", len(self.entropy_baseline))

    def should_trigger_response(self):
        score, _ = self.compute_threat_score()
        return score >= self.cfg.THREAT_SCORE_KILL_THRESHOLD

    def get_threat_summary(self):
        score, reasons = self.compute_threat_score()
        with self._lock:
            self._prune_all()
            rename_rate = len(self.rename_timestamps) / max(self.cfg.DETECTION_WINDOW, 1)
            write_rate = len(self.write_timestamps) / max(self.cfg.DETECTION_WINDOW, 1)
        return {
            "score": score,
            "threshold": self.cfg.THREAT_SCORE_KILL_THRESHOLD,
            "max_possible": sum(self.cfg.SIGNAL_WEIGHTS.values()),
            "reasons": reasons,
            "rename_rate": round(rename_rate, 2),
            "write_rate": round(write_rate, 2),
        }

    def reset(self):
        with self._lock:
            self.encrypted_rename_timestamps.clear()
            self.rename_timestamps.clear()
            self.write_timestamps.clear()
            self.entropy_spike_timestamps.clear()
            self.ransom_note_timestamps.clear()
            self.yara_match_timestamps.clear()
            self.entropy_baseline.clear()
        logger.info("Analyzer state reset")
