import os
import time
import logging
import psutil
from datetime import datetime

logger = logging.getLogger(__name__)


class ResponseHandler:
    def __init__(self, cfg, event_store, shadow_manager, reporter=None):
        self.cfg = cfg
        self.event_store = event_store
        self.shadow = shadow_manager
        self.reporter = reporter

    def identify_suspect_processes(self, target_dir):
        suspects = []

        pid_path = self.cfg.PID_FILE
        if os.path.exists(pid_path):
            try:
                with open(pid_path, "r") as f:
                    pid = int(f.read().strip())
                proc = psutil.Process(pid)
                if proc.is_running():
                    suspects.append(proc)
                    logger.info("Suspect identified via PID file: %d", pid)
            except (ValueError, psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if not suspects:
            target_norm = os.path.normpath(target_dir).lower()
            seen_pids = {os.getpid()}
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    if proc.pid in seen_pids:
                        continue
                    open_files = proc.open_files()
                    for f in open_files:
                        if target_norm in os.path.normpath(f.path).lower():
                            suspects.append(proc)
                            seen_pids.add(proc.pid)
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        return suspects

    def build_process_tree(self, proc):
        tree = {}
        try:
            tree["pid"] = proc.pid
            tree["name"] = proc.name()
            tree["status"] = proc.status()
            tree["cpu_percent"] = proc.cpu_percent(interval=0.1)
            tree["memory_mb"] = round(proc.memory_info().rss / (1024 * 1024), 2)
            tree["create_time"] = datetime.fromtimestamp(proc.create_time()).isoformat()

            cmdline = proc.cmdline()
            tree["cmdline"] = " ".join(cmdline[:6]) if cmdline else proc.name()

            tree["children"] = []
            for child in proc.children(recursive=True):
                try:
                    tree["children"].append({
                        "pid": child.pid,
                        "name": child.name(),
                        "status": child.status(),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            try:
                parent = proc.parent()
                if parent:
                    tree["parent"] = {"pid": parent.pid, "name": parent.name()}
                else:
                    tree["parent"] = None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                tree["parent"] = None

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return tree

    def kill_process(self, proc, reason):
        proc_name = "unknown"
        pid = -1

        try:
            pid = proc.pid
            proc_name = proc.name()

            tree = self.build_process_tree(proc)
            self.event_store.update_process_tree(tree)

            for child in proc.children(recursive=True):
                try:
                    child.terminate()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            proc.terminate()

            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    pass

            self.event_store.add_kill_decision(
                pid, proc_name, reason, "terminated"
            )
            logger.info("Process killed: %s (PID %d)", proc_name, pid)
            return True

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.event_store.add_kill_decision(
                pid, proc_name, reason, f"failed ({e})"
            )
            logger.warning("Failed to kill process %d: %s", pid, e)
            return False

    def rollback(self):
        self.event_store.add_event(
            "ROLLBACK_START", "info", "Initiating rollback from shadow copy..."
        )

        count, details = self.shadow.rollback()

        for detail in details:
            self.event_store.add_event("ROLLBACK_DETAIL", "info", detail)

        self.event_store.add_event(
            "ROLLBACK_COMPLETE",
            "info",
            f"Rollback finished: {count} operations performed",
            {"restored_count": count, "details": details},
        )

        return count, details

    def execute_response(self, target_dir, threat_summary):
        self.event_store.add_event(
            "RESPONSE_INITIATED",
            "critical",
            f"Threat score {threat_summary['score']} exceeded threshold "
            f"({threat_summary['threshold']}). Engaging response protocol.",
            threat_summary,
        )

        suspects = self.identify_suspect_processes(target_dir)
        killed = False

        for proc in suspects:
            reason = "; ".join(threat_summary["reasons"][:5])
            killed = self.kill_process(proc, reason)
            if killed:
                break

        if not killed and suspects:
            self.event_store.add_event(
                "RESPONSE_WARNING",
                "high",
                "Failed to kill identified suspect process. Proceeding with rollback.",
            )
        elif not suspects:
            self.event_store.add_event(
                "RESPONSE_WARNING",
                "high",
                "No suspect process identified. Proceeding with rollback.",
            )

        time.sleep(2)

        count, details = self.rollback()

        self.event_store.add_event(
            "RESPONSE_COMPLETE",
            "info",
            f"Incident response complete. Process killed: {killed}. "
            f"Rollback operations: {count}.",
        )

        if self.reporter:
            try:
                self.reporter.generate_report(
                    threat_summary,
                    self.event_store.get_all(),
                )
            except Exception as e:
                logger.warning("Report generation failed: %s", e)

        return killed, count
