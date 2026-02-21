import os
import time
import random
import logging
from datetime import datetime

import config
from simulator.payloads import (
    generate_high_entropy_content,
    generate_moderate_entropy_content,
    generate_ransom_note,
)

logger = logging.getLogger(__name__)

STEALTH_EXTENSIONS = [".bak", ".tmp", ".old"]


class RansomwareSimulator:
    def __init__(self, target_dir=None, speed="normal", stealth=False):
        self.target_dir = target_dir or config.SANDBOX_DIR
        self.pid = os.getpid()
        self.speed = speed
        self.stealth = stealth
        self.running = True
        self.files_processed = 0
        self.start_time = None
        self.writes_per_file = (4, 10) if not stealth else (1, 3)

        if stealth:
            delays = {"fast": (0.8, 1.5), "normal": (2.0, 4.0), "slow": (4.0, 8.0)}
        else:
            delays = {"fast": (0.05, 0.15), "normal": (0.3, 0.8), "slow": (1.0, 2.5)}
        self.delay_range = delays.get(speed, delays["normal"])

    def _write_pid(self):
        with open(config.PID_FILE, "w") as f:
            f.write(str(self.pid))

    def _cleanup_pid(self):
        try:
            if os.path.exists(config.PID_FILE):
                os.remove(config.PID_FILE)
        except OSError:
            pass

    def _get_target_files(self):
        targets = []
        for entry in os.scandir(self.target_dir):
            if entry.is_file() and not entry.name.endswith(config.ENCRYPTED_EXTENSION):
                if entry.name not in ("RANSOM_NOTE.txt", "README_DECRYPT.html"):
                    targets.append(entry.path)
        random.shuffle(targets)
        return targets

    def _spike_io(self, filepath):
        with open(filepath, "rb") as f:
            original_data = f.read()

        if self.stealth:
            payload = generate_moderate_entropy_content(original_data)
        else:
            payload = generate_high_entropy_content(len(original_data))

        for _ in range(random.randint(*self.writes_per_file)):
            with open(filepath, "wb") as f:
                f.write(payload)
            time.sleep(0.02)

        return original_data

    def _encrypt_file(self, filepath, original_data):
        if self.stealth:
            payload = generate_moderate_entropy_content(original_data)
            new_ext = random.choice(STEALTH_EXTENSIONS)
        else:
            payload = generate_high_entropy_content(max(len(original_data), 256))
            new_ext = config.ENCRYPTED_EXTENSION

        with open(filepath, "wb") as f:
            f.write(payload)

        encrypted_path = filepath + new_ext
        try:
            os.replace(filepath, encrypted_path)
        except OSError as e:
            logger.debug("Rename failed for %s: %s", filepath, e)
            return filepath

        self.files_processed += 1
        return encrypted_path

    def _drop_ransom_note(self):
        note_txt = os.path.join(self.target_dir, "RANSOM_NOTE.txt")
        note_html = os.path.join(self.target_dir, "README_DECRYPT.html")
        txt_content, html_content = generate_ransom_note()

        with open(note_txt, "w", encoding="utf-8") as f:
            f.write(txt_content)
        with open(note_html, "w", encoding="utf-8") as f:
            f.write(html_content)

    def run(self):
        self.start_time = datetime.now()
        self._write_pid()

        mode = "STEALTH" if self.stealth else "NORMAL"
        print(f"[SIM] PID {self.pid} | Target: {self.target_dir}")
        print(f"[SIM] Mode: {mode} | Speed: {self.speed} | Delay: {self.delay_range[0]}-{self.delay_range[1]}s")
        print("[SIM] Starting in 3 seconds (start the detector first if not running)...")
        time.sleep(3)

        targets = self._get_target_files()
        if not targets:
            print("[SIM] No target files found in sandbox.")
            self._cleanup_pid()
            return

        print(f"[SIM] Found {len(targets)} target files. Beginning simulation...")

        for filepath in targets:
            if not self.running:
                print("[SIM] Terminated by external signal.")
                break

            filename = os.path.basename(filepath)
            print(f"[SIM] Processing: {filename}")

            try:
                original_data = self._spike_io(filepath)
                encrypted = self._encrypt_file(filepath, original_data)
                print(f"[SIM]   -> {os.path.basename(encrypted)}")

                if not self.stealth:
                    if self.files_processed == 1 or self.files_processed == len(targets) // 2:
                        self._drop_ransom_note()
                        print("[SIM]   -> Dropped ransom note")

                delay = random.uniform(*self.delay_range)
                time.sleep(delay)

            except (PermissionError, FileNotFoundError, OSError) as e:
                print(f"[SIM] Skipped {filename}: {e}")
                continue

        if self.running:
            if not self.stealth:
                self._drop_ransom_note()
            elapsed = (datetime.now() - self.start_time).total_seconds()
            print(f"[SIM] Complete. {self.files_processed} files processed in {elapsed:.1f}s")

        self._cleanup_pid()

    def stop(self):
        self.running = False
