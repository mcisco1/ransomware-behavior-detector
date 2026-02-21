import os
import json
import time
import shutil
import hashlib
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ShadowManager:
    def __init__(self, source_dir, shadow_dir):
        self.source_dir = source_dir
        self.shadow_dir = shadow_dir
        self.manifest_path = os.path.join(shadow_dir, "manifest.json")
        self.manifest = {}

    def create_snapshot(self):
        os.makedirs(self.shadow_dir, exist_ok=True)
        self.manifest = {}

        for entry in os.scandir(self.source_dir):
            if not entry.is_file():
                continue

            src_path = entry.path
            filename = entry.name
            shadow_path = os.path.join(self.shadow_dir, filename)

            try:
                shutil.copy2(src_path, shadow_path)

                with open(shadow_path, "rb") as f:
                    content = f.read()

                self.manifest[filename] = {
                    "original_path": src_path,
                    "shadow_path": shadow_path,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                    "snapshot_time": datetime.now().isoformat(),
                }
            except OSError as e:
                logger.warning("Could not snapshot %s: %s", filename, e)

        with open(self.manifest_path, "w") as f:
            json.dump(self.manifest, f, indent=2)

        logger.info("Shadow snapshot: %d files backed up", len(self.manifest))
        return len(self.manifest)

    def rollback(self):
        if not os.path.exists(self.manifest_path):
            return 0, []

        with open(self.manifest_path, "r") as f:
            self.manifest = json.load(f)

        restored = []
        original_filenames = set(self.manifest.keys())

        for attempt in range(6):
            extras = []
            for entry in os.scandir(self.source_dir):
                if entry.is_file() and entry.name not in original_filenames:
                    extras.append(entry.name)

            if not extras:
                break

            for name in extras:
                path = os.path.join(self.source_dir, name)
                try:
                    os.remove(path)
                    restored.append(f"Removed: {name}")
                    logger.debug("Removed extra file: %s", name)
                except OSError:
                    pass

            if attempt < 5:
                time.sleep(0.5)

        for filename, info in self.manifest.items():
            shadow_path = info["shadow_path"]
            original_path = info["original_path"]

            if not os.path.exists(shadow_path):
                continue

            needs_restore = False
            if not os.path.exists(original_path):
                needs_restore = True
            else:
                try:
                    with open(original_path, "rb") as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != info["sha256"]:
                        needs_restore = True
                except OSError:
                    needs_restore = True

            if needs_restore:
                try:
                    shutil.copy2(shadow_path, original_path)
                    restored.append(f"Restored: {filename}")
                    logger.debug("Restored: %s", filename)
                except OSError as e:
                    logger.warning("Could not restore %s: %s", filename, e)

        logger.info("Rollback complete: %d operations", len(restored))
        return len(restored), restored

    def verify_integrity(self):
        if not self.manifest and os.path.exists(self.manifest_path):
            with open(self.manifest_path, "r") as f:
                self.manifest = json.load(f)

        results = {}
        for filename, info in self.manifest.items():
            shadow_path = info["shadow_path"]
            if os.path.exists(shadow_path):
                with open(shadow_path, "rb") as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                results[filename] = current_hash == info["sha256"]
            else:
                results[filename] = False

        return results
