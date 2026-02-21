import os
import pytest

from detector.events import EventStore
from detector.shadow import ShadowManager


class _TestConfig:
    SANDBOX_DIR = ""
    SHADOW_DIR = ""
    PID_FILE = ""
    LOG_DIR = ""
    REPORT_DIR = ""
    YARA_RULES_DIR = ""
    DASHBOARD_HOST = "127.0.0.1"
    DASHBOARD_PORT = 5000
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


@pytest.fixture
def mock_config(tmp_path):
    cfg = _TestConfig()
    cfg.SANDBOX_DIR = str(tmp_path / "sandbox")
    cfg.SHADOW_DIR = str(tmp_path / "shadow")
    cfg.PID_FILE = str(tmp_path / ".simulator.pid")
    cfg.LOG_DIR = str(tmp_path / "logs")
    cfg.REPORT_DIR = str(tmp_path / "reports")
    cfg.YARA_RULES_DIR = str(tmp_path / "rules")
    os.makedirs(cfg.SANDBOX_DIR, exist_ok=True)
    os.makedirs(cfg.SHADOW_DIR, exist_ok=True)
    return cfg


@pytest.fixture
def event_store():
    return EventStore()


@pytest.fixture
def sandbox(mock_config):
    files = {
        "report.docx": b"Quarterly financial report with detailed analysis",
        "data.csv": b"name,dept,salary\nJohn,Eng,95000\nJane,Mkt,87000",
        "notes.txt": b"Meeting notes from the weekly standup session",
        "code.py": b"import hashlib\ndef hash_data(d): return hashlib.sha256(d).hexdigest()",
        "config.yaml": b"server:\n  host: 0.0.0.0\n  port: 8080\n",
    }
    for name, content in files.items():
        filepath = os.path.join(mock_config.SANDBOX_DIR, name)
        with open(filepath, "wb") as f:
            f.write(content)
    return mock_config.SANDBOX_DIR


@pytest.fixture
def shadow(mock_config, sandbox):
    mgr = ShadowManager(mock_config.SANDBOX_DIR, mock_config.SHADOW_DIR)
    mgr.create_snapshot()
    return mgr
