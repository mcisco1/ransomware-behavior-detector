import os
import pytest

from detector.shadow import ShadowManager


class TestShadowManager:
    def test_snapshot_creates_copies(self, shadow, mock_config):
        for name in os.listdir(mock_config.SANDBOX_DIR):
            shadow_path = os.path.join(mock_config.SHADOW_DIR, name)
            assert os.path.exists(shadow_path)

    def test_snapshot_contains_all_files(self, shadow, mock_config):
        sandbox_files = set(os.listdir(mock_config.SANDBOX_DIR))
        assert set(shadow.manifest.keys()) == sandbox_files

    def test_rollback_restores_modified_files(self, shadow, mock_config):
        target = os.path.join(mock_config.SANDBOX_DIR, "report.docx")
        with open(target, "wb") as f:
            f.write(os.urandom(256))

        count, details = shadow.rollback()
        assert count > 0

        with open(target, "rb") as f:
            content = f.read()
        assert content == b"Quarterly financial report with detailed analysis"

    def test_rollback_removes_extra_files(self, shadow, mock_config):
        extra = os.path.join(mock_config.SANDBOX_DIR, "RANSOM_NOTE.txt")
        with open(extra, "w") as f:
            f.write("Your files have been encrypted")

        count, details = shadow.rollback()
        assert not os.path.exists(extra)
        assert any("Removed" in d for d in details)

    def test_rollback_restores_deleted_files(self, shadow, mock_config):
        target = os.path.join(mock_config.SANDBOX_DIR, "notes.txt")
        os.remove(target)
        assert not os.path.exists(target)

        shadow.rollback()
        assert os.path.exists(target)

    def test_integrity_passes_on_clean_shadow(self, shadow):
        results = shadow.verify_integrity()
        assert all(results.values())

    def test_full_attack_rollback(self, shadow, mock_config):
        sandbox = mock_config.SANDBOX_DIR
        original_files = set(os.listdir(sandbox))

        for name in list(os.listdir(sandbox)):
            filepath = os.path.join(sandbox, name)
            with open(filepath, "wb") as f:
                f.write(os.urandom(256))
            os.replace(filepath, filepath + ".encrypted")

        with open(os.path.join(sandbox, "RANSOM_NOTE.txt"), "w") as f:
            f.write("encrypted bitcoin ransom")

        shadow.rollback()

        final_files = set(os.listdir(sandbox))
        assert final_files == original_files
