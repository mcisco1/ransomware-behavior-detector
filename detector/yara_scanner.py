import os
import logging

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraScanner:
    def __init__(self, rules_dir):
        self.available = False
        self.rules = None
        self.rule_count = 0

        if not YARA_AVAILABLE:
            logger.info("yara-python not installed; YARA scanning disabled")
            return

        if not os.path.isdir(rules_dir):
            logger.info("YARA rules directory not found: %s", rules_dir)
            return

        rule_files = {}
        for entry in os.scandir(rules_dir):
            if entry.is_file() and entry.name.endswith((".yar", ".yara")):
                ns = os.path.splitext(entry.name)[0]
                rule_files[ns] = entry.path

        if not rule_files:
            logger.info("No YARA rule files found in %s", rules_dir)
            return

        try:
            self.rules = yara.compile(filepaths=rule_files)
            self.rule_count = len(rule_files)
            self.available = True
            logger.info("YARA scanner loaded %d rule file(s)", self.rule_count)
        except Exception as e:
            logger.warning("Failed to compile YARA rules: %s", e)

    def scan_file(self, filepath):
        if not self.available or not self.rules:
            return []
        try:
            matches = self.rules.match(filepath)
            return matches
        except Exception as e:
            logger.debug("YARA scan failed for %s: %s", filepath, e)
            return []
