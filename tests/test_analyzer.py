import os
import time
import pytest

from utils import shannon_entropy
from detector.events import EventStore
from detector.analyzer import BehavioralAnalyzer


class TestShannonEntropy:
    def test_empty_data_returns_zero(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte_value_returns_zero(self):
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_random_data_near_eight(self):
        data = os.urandom(4096)
        assert shannon_entropy(data) > 7.0

    def test_text_moderate_entropy(self):
        data = b"The quick brown fox jumps over the lazy dog. " * 10
        e = shannon_entropy(data)
        assert 3.0 < e < 6.0

    def test_two_byte_values_returns_one(self):
        data = bytes([0, 1] * 500)
        assert abs(shannon_entropy(data) - 1.0) < 0.01


class TestBehavioralAnalyzer:
    @pytest.fixture
    def analyzer(self, mock_config):
        store = EventStore()
        return BehavioralAnalyzer(mock_config, store)

    def test_initial_score_is_zero(self, analyzer):
        score, reasons = analyzer.compute_threat_score()
        assert score == 0
        assert reasons == []

    def test_encrypted_rename_adds_signal(self, analyzer):
        analyzer.record_rename("/tmp/a.txt", "/tmp/a.txt.encrypted")
        score, reasons = analyzer.compute_threat_score()
        assert score == 15
        assert len(reasons) == 1

    def test_score_is_bounded(self, analyzer, mock_config):
        max_score = sum(mock_config.SIGNAL_WEIGHTS.values())
        for i in range(50):
            analyzer.record_rename(f"/tmp/{i}.txt", f"/tmp/{i}.txt.encrypted")
            analyzer.record_write(f"/tmp/{i}.txt")
        score, _ = analyzer.compute_threat_score()
        assert score <= max_score

    def test_multiple_encrypted_renames_score_once(self, analyzer):
        for i in range(10):
            analyzer.record_rename(f"/tmp/{i}.txt", f"/tmp/{i}.txt.encrypted")
        score, reasons = analyzer.compute_threat_score()
        assert score >= 15
        encrypted_reasons = [r for r in reasons if "encrypted extension" in r]
        assert len(encrypted_reasons) == 1

    def test_score_decays_after_window(self, analyzer, mock_config):
        mock_config.DETECTION_WINDOW = 0.1
        analyzer.record_rename("/tmp/a.txt", "/tmp/a.txt.encrypted")
        score1, _ = analyzer.compute_threat_score()
        assert score1 > 0

        time.sleep(0.2)
        score2, _ = analyzer.compute_threat_score()
        assert score2 == 0

    def test_ransom_note_detection(self, analyzer, tmp_path):
        note = tmp_path / "ransom.txt"
        note.write_text(
            "Your files have been encrypted. Send bitcoin to our wallet. "
            "Payment deadline is 48 hours. Decrypt key will be provided."
        )
        result = analyzer.check_ransom_note(str(note))
        assert result is True
        score, reasons = analyzer.compute_threat_score()
        assert score >= 30

    def test_no_false_positive_on_normal_files(self, analyzer, tmp_path):
        normal = tmp_path / "readme.txt"
        normal.write_text("This is a normal project readme with setup instructions.")
        result = analyzer.check_ransom_note(str(normal))
        assert result is False

    def test_entropy_spike_detection(self, analyzer):
        high_entropy_file = os.path.join(os.path.dirname(__file__), "_temp_entropy_test")
        analyzer.entropy_baseline["_temp_entropy_test"] = 3.5
        try:
            with open(high_entropy_file, "wb") as f:
                f.write(os.urandom(1024))
            analyzer.analyze_entropy(high_entropy_file)
        finally:
            if os.path.exists(high_entropy_file):
                os.remove(high_entropy_file)
        score, _ = analyzer.compute_threat_score()
        assert score >= 20

    def test_reset_clears_state(self, analyzer):
        analyzer.record_rename("/tmp/a.txt", "/tmp/a.txt.encrypted")
        score1, _ = analyzer.compute_threat_score()
        assert score1 > 0

        analyzer.reset()
        score2, _ = analyzer.compute_threat_score()
        assert score2 == 0

    def test_get_threat_summary_structure(self, analyzer):
        summary = analyzer.get_threat_summary()
        assert "score" in summary
        assert "threshold" in summary
        assert "max_possible" in summary
        assert "reasons" in summary
        assert "rename_rate" in summary
        assert "write_rate" in summary
        assert summary["score"] == 0
