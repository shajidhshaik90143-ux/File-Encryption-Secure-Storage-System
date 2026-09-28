from __future__ import annotations
import argparse
import getpass
from pathlib import Path
from src.crypto_engine import encrypt_file, decrypt_file, is_encrypted_file, AuthenticationError
from src.vault import Vault
from src.audit import AuditLogger

def main():
    parser = argparse.ArgumentParser(description="File Encryption & Secure Storage System")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    p = sub.add_parser("encrypt"); p.add_argument("file")
    p = sub.add_parser("decrypt"); p.add_argument("file")
    p = sub.add_parser("verify"); p.add_argument("file")
    args = parser.parse_args()

    vault = Vault()
    audit = AuditLogger()

    if args.cmd == "init":
        pw = getpass.getpass("Create vault password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            raise SystemExit("Passwords do not match")
        vault.create(pw)
        print("Vault initialized.")
        return

    pw = getpass.getpass("Vault password: ")
    if not vault.verify(pw):
        audit.event(args.cmd, "DENIED")
        raise SystemExit("Invalid vault password")

    target = Path(args.file)
    if args.cmd == "encrypt":
        out = vault.root / (target.name + ".fes")
        encrypt_file(target, out, pw)
        audit.event("encrypt", "SUCCESS", target)
        print(f"Encrypted: {out}")
    elif args.cmd == "decrypt":
        if not is_encrypted_file(target):
            raise SystemExit("Not a supported encrypted file")
        out = target.with_suffix("")
        decrypt_file(target, out, pw)
        audit.event("decrypt", "SUCCESS", target)
        print(f"Decrypted: {out}")
    elif args.cmd == "verify":
        try:
            temp = target.with_name(".__verify_temp__")
            decrypt_file(target, temp, pw)
            temp.unlink(missing_ok=True)
            print("Integrity/authentication check: PASSED")
        except AuthenticationError:
            print("Integrity/authentication check: FAILED")

if __name__ == "__main__":
    main()
