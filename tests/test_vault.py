import tempfile
import unittest
from pathlib import Path
from src.vault import Vault

class VaultTests(unittest.TestCase):
    def test_create_and_verify(self):
        with tempfile.TemporaryDirectory() as d:
            v = Vault(Path(d) / "vault")
            v.create("strong-password")
            self.assertTrue(v.verify("strong-password"))
            self.assertFalse(v.verify("wrong-password"))

if __name__ == "__main__":
    unittest.main()
