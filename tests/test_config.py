import pytest
import config


def test_validate_passes_with_defaults():
    config.validate_config()


def test_catches_negative_detection_window(monkeypatch):
    monkeypatch.setattr(config, "DETECTION_WINDOW", -1)
    with pytest.raises(ValueError, match="DETECTION_WINDOW"):
        config.validate_config()


def test_catches_excessive_detection_window(monkeypatch):
    monkeypatch.setattr(config, "DETECTION_WINDOW", 999)
    with pytest.raises(ValueError, match="DETECTION_WINDOW"):
        config.validate_config()


def test_catches_bad_port(monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_PORT", 99999)
    with pytest.raises(ValueError, match="DASHBOARD_PORT"):
        config.validate_config()


def test_catches_zero_threshold(monkeypatch):
    monkeypatch.setattr(config, "THREAT_SCORE_KILL_THRESHOLD", 0)
    with pytest.raises(ValueError, match="THREAT_SCORE_KILL_THRESHOLD"):
        config.validate_config()


def test_catches_threshold_exceeding_max_score(monkeypatch):
    monkeypatch.setattr(config, "THREAT_SCORE_KILL_THRESHOLD", 9999)
    with pytest.raises(ValueError, match="exceeds"):
        config.validate_config()


def test_catches_bad_entropy_jump(monkeypatch):
    monkeypatch.setattr(config, "ENTROPY_JUMP_THRESHOLD", -1)
    with pytest.raises(ValueError, match="ENTROPY_JUMP_THRESHOLD"):
        config.validate_config()


def test_catches_empty_keywords(monkeypatch):
    monkeypatch.setattr(config, "RANSOM_NOTE_KEYWORDS", [])
    with pytest.raises(ValueError, match="RANSOM_NOTE_KEYWORDS"):
        config.validate_config()


def test_signal_weights_defined():
    assert "encrypted_rename" in config.SIGNAL_WEIGHTS
    assert "rapid_rename_rate" in config.SIGNAL_WEIGHTS
    assert "high_write_volume" in config.SIGNAL_WEIGHTS
    assert "entropy_spike" in config.SIGNAL_WEIGHTS
    assert "ransom_note" in config.SIGNAL_WEIGHTS
    assert all(w > 0 for w in config.SIGNAL_WEIGHTS.values())
