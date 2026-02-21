import os
import random
import string
from datetime import datetime, timedelta, timezone

from utils import shannon_entropy


def generate_high_entropy_content(size):
    return os.urandom(max(size, 64))


def generate_moderate_entropy_content(original_data):
    result = bytearray(original_data)
    if not result:
        return bytes(result)
    chunk_size = max(len(result) // 4, 16)
    num_chunks = max(1, len(result) // chunk_size // 3)
    for _ in range(num_chunks):
        start = random.randint(0, max(0, len(result) - chunk_size))
        end = min(start + chunk_size, len(result))
        result[start:end] = os.urandom(end - start)
    return bytes(result)


def generate_ransom_note():
    deadline = datetime.now(timezone.utc) + timedelta(hours=random.randint(24, 72))
    wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    amount = round(random.uniform(0.5, 2.5), 4)
    victim_id = "".join(random.choices(string.ascii_uppercase + string.digits, k=16))

    txt_note = f"""========================================
     YOUR FILES HAVE BEEN ENCRYPTED
========================================

All documents, databases, and files in this
directory have been locked with military-grade
encryption. You cannot decrypt them without
our private key.

VICTIM ID: {victim_id}

TO RECOVER YOUR FILES:

  1. Send {amount} BTC to wallet:
     {wallet}

  2. Email your VICTIM ID to confirm payment

  3. Receive decryption tool within 24 hours

DEADLINE: {deadline.strftime("%Y-%m-%d %H:%M UTC")}

After the deadline, the price doubles.
After 7 days, your key is permanently deleted.

DO NOT:
  - Rename encrypted files
  - Use third-party decryption tools
  - Contact law enforcement

========================================
"""

    html_note = f"""<!DOCTYPE html>
<html><head><title>Files Encrypted</title>
<style>
body {{ background:#1a0000; color:#ff3333; font-family:monospace; padding:40px; }}
.box {{ max-width:700px; margin:0 auto; border:2px solid #ff3333; padding:30px; }}
h1 {{ text-align:center; font-size:28px; }}
.warn {{ background:#330000; padding:15px; margin:20px 0; border-left:4px solid #ff0000; }}
.addr {{ background:#0a0a0a; padding:10px; font-size:14px; word-break:break-all; }}
.timer {{ color:#ff6600; font-size:20px; text-align:center; margin:20px 0; }}
</style></head>
<body><div class="box">
<h1>YOUR FILES HAVE BEEN ENCRYPTED</h1>
<div class="warn">
All files in this directory have been locked with strong encryption.
Payment is required to recover them.
</div>
<p><strong>Victim ID:</strong> {victim_id}</p>
<p><strong>Amount:</strong> {amount} BTC</p>
<p><strong>Wallet:</strong></p>
<div class="addr">{wallet}</div>
<div class="timer">DEADLINE: {deadline.strftime("%Y-%m-%d %H:%M UTC")}</div>
<p style="font-size:12px;color:#993333;">
Do not attempt to rename files or use third-party recovery tools.
Doing so will permanently destroy your data.
</p>
</div></body></html>"""

    return txt_note, html_note
