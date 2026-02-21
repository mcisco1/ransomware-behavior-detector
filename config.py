import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SANDBOX_DIR = os.path.join(BASE_DIR, "sandbox")
SHADOW_DIR = os.path.join(BASE_DIR, ".shadow")
PID_FILE = os.path.join(BASE_DIR, ".simulator.pid")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
YARA_RULES_DIR = os.path.join(BASE_DIR, "rules")

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000

# --- Detection Thresholds ---
RENAME_RATE_THRESHOLD = 3
WRITE_VOLUME_THRESHOLD = 30
ENTROPY_JUMP_THRESHOLD = 2.0
HIGH_ENTROPY_THRESHOLD = 7.0

RANSOM_NOTE_KEYWORDS = [
    "encrypted", "bitcoin", "btc", "ransom", "decrypt",
    "payment", "wallet", "locked", "recover", "deadline",
]

DETECTION_WINDOW = 5
ENCRYPTED_EXTENSION = ".encrypted"
THREAT_SCORE_KILL_THRESHOLD = 50

SIGNAL_WEIGHTS = {
    "encrypted_rename": 15,
    "rapid_rename_rate": 25,
    "high_write_volume": 20,
    "entropy_spike": 20,
    "ransom_note": 30,
    "yara_match": 30,
}


def validate_config():
    errors = []

    if DETECTION_WINDOW <= 0:
        errors.append("DETECTION_WINDOW must be positive")
    if DETECTION_WINDOW > 300:
        errors.append("DETECTION_WINDOW should not exceed 300 seconds")

    if not (1 <= DASHBOARD_PORT <= 65535):
        errors.append("DASHBOARD_PORT must be between 1 and 65535")

    if THREAT_SCORE_KILL_THRESHOLD <= 0:
        errors.append("THREAT_SCORE_KILL_THRESHOLD must be positive")

    max_possible = sum(SIGNAL_WEIGHTS.values())
    if THREAT_SCORE_KILL_THRESHOLD > max_possible:
        errors.append(
            f"THREAT_SCORE_KILL_THRESHOLD ({THREAT_SCORE_KILL_THRESHOLD}) "
            f"exceeds maximum possible score ({max_possible})"
        )

    if ENTROPY_JUMP_THRESHOLD < 0:
        errors.append("ENTROPY_JUMP_THRESHOLD must be non-negative")

    if not RANSOM_NOTE_KEYWORDS:
        errors.append("RANSOM_NOTE_KEYWORDS must not be empty")

    if not all(w > 0 for w in SIGNAL_WEIGHTS.values()):
        errors.append("All SIGNAL_WEIGHTS must be positive")

    if errors:
        raise ValueError(
            "Configuration errors:\n  " + "\n  ".join(errors)
        )
