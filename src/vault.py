from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from .crypto_engine import PBKDF2_ITERATIONS

META_NAME = ".vault.json"
VERIFY_SALT_LEN = 16

class Vault:
    def __init__(self, root="data/vault"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.meta = self.root / META_NAME

    def exists(self):
        return self.meta.exists()

    def create(self, password):
        if self.exists():
            raise FileExistsError("Vault already initialized")
        if len(password) < 8:
            raise ValueError("Use a password of at least 8 characters")
        salt = os.urandom(VERIFY_SALT_LEN)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
        data = {
            "version": 1,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode(),
            "verifier": base64.b64encode(digest).decode(),
        }
        self.meta.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            os.chmod(self.meta, 0o600)
        except OSError:
            pass

    def verify(self, password):
        if not self.exists():
            return False
        data = json.loads(self.meta.read_text(encoding="utf-8"))
        salt = base64.b64decode(data["salt"])
        expected = base64.b64decode(data["verifier"])
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(data["iterations"]))
        return hmac.compare_digest(expected, actual)

    def files(self):
        return sorted(p for p in self.root.iterdir() if p.name != META_NAME and p.is_file())
