# File Encryption & Secure Storage System

A strong educational security project for encrypting, decrypting, and securely managing files.

## Features
- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 password-based key derivation
- Per-file random salt and nonce
- Password verification without storing the password
- File integrity/authentication validation
- Encrypt single files or folders
- Decrypt encrypted files
- Secure vault directory
- SHA-256 fingerprints for audit records
- Security event logging
- Streamlit dashboard
- No plaintext password storage
- Atomic output writes to reduce partial-file corruption

## Important security note
This is a project/demo implementation, not a replacement for professional enterprise key management. Keep strong passwords and back up encrypted files and passwords separately.

## Requirements
Python 3.10+ recommended.

## Windows setup
```powershell
cd "File Encryption & Secure Storage System"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation:
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

## CLI
Initialize a vault:
```powershell
python cli.py init
```

Encrypt:
```powershell
python cli.py encrypt "C:\Users\admin\Documents\secret.pdf"
```

Decrypt:
```powershell
python cli.py decrypt "data\vault\secret.pdf.fes"
```

Verify:
```powershell
python cli.py verify "data\vault\secret.pdf.fes"
```

## Run tests
```powershell
python -m unittest discover -s tests -v
```

## Project structure
- `app.py` - Streamlit UI
- `cli.py` - command-line interface
- `src/crypto_engine.py` - encryption/decryption engine
- `src/vault.py` - vault and password metadata management
- `src/audit.py` - security audit logging
- `src/utils.py` - hashing, file utilities, atomic writes
- `tests/` - automated tests
- `data/vault/` - encrypted files
- `logs/` - audit logs

Encrypted file format starts with a versioned magic header and contains:
magic + version + salt + nonce + original filename length + original filename + ciphertext/tag.
AES-GCM authentication detects wrong passwords and modified ciphertext.
