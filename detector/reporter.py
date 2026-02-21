import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class IncidentReporter:
    def __init__(self, report_dir):
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)

    def generate_report(self, threat_summary, event_data):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        incident_id = f"INC-{timestamp}"
        filename = f"{incident_id}.json"
        filepath = os.path.join(self.report_dir, filename)

        report = {
            "incident_id": incident_id,
            "generated_at": datetime.now().isoformat(),
            "threat_summary": {
                "score": threat_summary.get("score", 0),
                "threshold": threat_summary.get("threshold", 0),
                "max_possible": threat_summary.get("max_possible", 0),
                "reasons": threat_summary.get("reasons", []),
            },
            "kill_decisions": event_data.get("kill_decisions", []),
            "process_tree": event_data.get("process_tree", {}),
            "event_timeline": event_data.get("events", []),
            "event_count": len(event_data.get("events", [])),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info("Incident report written: %s", filepath)
        return filepath
