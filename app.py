from __future__ import annotations
import os
from pathlib import Path
import pandas as pd
import streamlit as st
from src.crypto_engine import encrypt_file, decrypt_file, is_encrypted_file, AuthenticationError, EncryptionError
from src.vault import Vault
from src.audit import AuditLogger
from src.utils import sha256_file

st.set_page_config(page_title="Secure Storage Vault", page_icon="🔐", layout="wide")

vault = Vault()
audit = AuditLogger()

st.title("🔐 File Encryption & Secure Storage System")
st.caption("AES-256-GCM • PBKDF2-HMAC-SHA256 • Authenticated encryption")

with st.sidebar:
    st.header("Vault")
    if not vault.exists():
        st.warning("Vault is not initialized.")
        p1 = st.text_input("Create password", type="password")
        p2 = st.text_input("Confirm password", type="password")
        if st.button("Initialize Vault", use_container_width=True):
            try:
                if p1 != p2:
                    st.error("Passwords do not match.")
                else:
                    vault.create(p1)
                    audit.event("vault_init", "SUCCESS")
                    st.success("Vault created. Refresh the page.")
                    st.rerun()
            except Exception as e:
                st.error(str(e))
        st.stop()

    password = st.text_input("Vault password", type="password")
    authenticated = bool(password) and vault.verify(password)
    if authenticated:
        st.success("Authenticated")
    elif password:
        st.error("Invalid password")

tabs = st.tabs(["📁 Encrypt", "🔓 Decrypt", "🛡️ Verify", "📊 Audit"])

with tabs[0]:
    st.subheader("Encrypt a file")
    if not authenticated:
        st.info("Enter your vault password in the sidebar.")
    else:
        uploaded = st.file_uploader("Choose a file", key="enc")
        if uploaded and st.button("Encrypt & Store", type="primary"):
            safe_name = Path(uploaded.name).name
            source = Path("data") / f".upload_{os.getpid()}_{safe_name}"
            source.parent.mkdir(exist_ok=True)
            source.write_bytes(uploaded.getvalue())
            out = vault.root / f"{safe_name}.fes"
            try:
                encrypt_file(source, out, password)
                audit.event("encrypt", "SUCCESS", safe_name, {"sha256": sha256_file(out)})
                st.success(f"Encrypted and stored: {out.name}")
                st.metric("Encrypted size", f"{out.stat().st_size:,} bytes")
            except Exception as e:
                audit.event("encrypt", "FAILED", safe_name, {"error": str(e)})
                st.error(str(e))
            finally:
                source.unlink(missing_ok=True)

with tabs[1]:
    st.subheader("Decrypt a stored file")
    if not authenticated:
        st.info("Enter your vault password in the sidebar.")
    else:
        encrypted = vault.files()
        choices = [p for p in encrypted if is_encrypted_file(p)]
        if not choices:
            st.info("No encrypted files in the vault.")
        else:
            selected = st.selectbox("Encrypted file", choices, format_func=lambda p: p.name)
            if st.button("Decrypt", type="primary"):
                out_dir = Path("data/decrypted")
                out_dir.mkdir(parents=True, exist_ok=True)
                out = out_dir / selected.stem
                try:
                    original = decrypt_file(selected, out, password)
                    audit.event("decrypt", "SUCCESS", selected.name)
                    st.success(f"Decrypted as: {out}")
                    st.download_button("Download decrypted file", out.read_bytes(), file_name=original)
                except AuthenticationError as e:
                    audit.event("decrypt", "DENIED", selected.name)
                    st.error(str(e))
                except Exception as e:
                    audit.event("decrypt", "FAILED", selected.name, {"error": str(e)})
                    st.error(str(e))

with tabs[2]:
    st.subheader("Integrity & authentication verification")
    if not authenticated:
        st.info("Enter your vault password in the sidebar.")
    else:
        choices = [p for p in vault.files() if is_encrypted_file(p)]
        if choices:
            selected = st.selectbox("File to verify", choices, key="verify")
            if st.button("Verify"):
                temp = Path("data") / f".verify_{os.getpid()}"
                try:
                    decrypt_file(selected, temp, password)
                    temp.unlink(missing_ok=True)
                    audit.event("verify", "PASSED", selected.name)
                    st.success("PASSED — password is valid and authenticated ciphertext verified.")
                except AuthenticationError:
                    temp.unlink(missing_ok=True)
                    audit.event("verify", "FAILED", selected.name)
                    st.error("FAILED — wrong password or encrypted file has been modified.")
        else:
            st.info("No encrypted files available.")

with tabs[3]:
    st.subheader("Security audit log")
    rows = audit.read_recent(200)
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No audit events yet.")

st.divider()
st.caption("Security design: plaintext passwords are never stored. AES-GCM provides confidentiality plus authenticated integrity.")
