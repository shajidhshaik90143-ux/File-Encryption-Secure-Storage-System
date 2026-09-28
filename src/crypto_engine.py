from __future__ import annotations
import os
import struct
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
from .utils import atomic_write

MAGIC = b"FES1"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
PBKDF2_ITERATIONS = 600_000
HEADER_FMT = "!4sB16s12sH"

class EncryptionError(Exception):
    pass

class AuthenticationError(EncryptionError):
    pass

def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(input_path: str | Path, output_path: str | Path, password: str):
    input_path, output_path = Path(input_path), Path(output_path)
    if not input_path.is_file():
        raise FileNotFoundError(input_path)
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    name = input_path.name.encode("utf-8")
    if len(name) > 65535:
        raise ValueError("Filename is too long")
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, salt, nonce, len(name)) + name
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)

    def writer(out):
        out.write(header)
        with input_path.open("rb") as src:
            while chunk := src.read(1024 * 1024):
                out.write(encryptor.update(chunk))
        out.write(encryptor.finalize())
        out.write(encryptor.tag)

    atomic_write(output_path, writer)

def _parse_header(f):
    fixed = f.read(struct.calcsize(HEADER_FMT))
    if len(fixed) != struct.calcsize(HEADER_FMT):
        raise EncryptionError("Invalid or truncated encrypted file")
    magic, version, salt, nonce, name_len = struct.unpack(HEADER_FMT, fixed)
    if magic != MAGIC or version != VERSION:
        raise EncryptionError("Unsupported encrypted file format")
    name = f.read(name_len)
    if len(name) != name_len:
        raise EncryptionError("Truncated encrypted header")
    header = fixed + name
    return header, salt, nonce, name.decode("utf-8", errors="strict")

def decrypt_file(input_path: str | Path, output_path: str | Path, password: str):
    input_path, output_path = Path(input_path), Path(output_path)
    size = input_path.stat().st_size
    with input_path.open("rb") as src:
        header, salt, nonce, original_name = _parse_header(src)
        header_len = len(header)
        if size < header_len + 16:
            raise EncryptionError("Encrypted file is truncated")
        ciphertext_len = size - header_len - 16
        key = derive_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
        decryptor.authenticate_additional_data(header)

        def writer(out):
            remaining = ciphertext_len
            while remaining:
                chunk = src.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise EncryptionError("Unexpected end of encrypted data")
                out.write(decryptor.update(chunk))
                remaining -= len(chunk)
            tag = src.read(16)
            try:
                out.write(decryptor.finalize_with_tag(tag))
            except InvalidTag as e:
                raise AuthenticationError("Authentication failed: wrong password or file was modified") from e

        atomic_write(output_path, writer)
    return original_name

def is_encrypted_file(path: str | Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except OSError:
        return False
