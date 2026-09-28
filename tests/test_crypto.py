import tempfile
import unittest
from pathlib import Path
from src.crypto_engine import encrypt_file, decrypt_file, AuthenticationError

class CryptoTests(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            src, enc, out = d/"hello.txt", d/"hello.txt.fes", d/"out.txt"
            payload = b"Secure storage test " * 10000
            src.write_bytes(payload)
            encrypt_file(src, enc, "correct horse battery staple")
            decrypt_file(enc, out, "correct horse battery staple")
            self.assertEqual(out.read_bytes(), payload)

    def test_wrong_password(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            src, enc, out = d/"a.txt", d/"a.txt.fes", d/"out.txt"
            src.write_bytes(b"secret")
            encrypt_file(src, enc, "strong-password")
            with self.assertRaises(AuthenticationError):
                decrypt_file(enc, out, "wrong-password")

    def test_tamper_detection(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            src, enc, out = d/"a.txt", d/"a.txt.fes", d/"out.txt"
            src.write_bytes(b"secret")
            encrypt_file(src, enc, "strong-password")
            data = bytearray(enc.read_bytes())
            data[-1] ^= 1
            enc.write_bytes(data)
            with self.assertRaises(AuthenticationError):
                decrypt_file(enc, out, "strong-password")

if __name__ == "__main__":
    unittest.main()
