# Security Notes

1. Use a unique strong vault password.
2. AES-256-GCM is used for authenticated encryption.
3. Each encrypted file receives a fresh random salt and nonce.
4. PBKDF2-HMAC-SHA256 uses 600,000 iterations.
5. Passwords are not stored; the vault metadata contains only a salted verifier.
6. Authentication failures are logged without recording the password.
7. Do not commit real encrypted data, vault metadata, or audit logs to public repositories.
8. Keep an independent backup of encrypted files.
