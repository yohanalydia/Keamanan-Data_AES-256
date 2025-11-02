# ============================================================
# 🔐 AES-256 CBC Streamlit App 
# ============================================================

# ============================================================
# IMPORT LIBRARY
# ============================================================
import streamlit as st                   # membuat GUI web interaktif
import pandas as pd                      # membaca/menampilkan data CSV & Excel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# Cipher: objek utama enkripsi/dekripsi
# algorithms: jenis algoritma kriptografi (AES)
# modes: mode operasi (CBC)

from cryptography.hazmat.primitives import padding
# untuk padding (PKCS7) agar panjang data kelipatan 16 byte (AES block size)

from cryptography.hazmat.backends import default_backend
# backend kriptografi OpenSSL

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# untuk derivasi kunci (key derivation) dari password

from cryptography.hazmat.primitives import hashes
# algoritma hash untuk PBKDF2 (misalnya SHA256)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# untuk enkripsi key (key wrapping) menggunakan AES-GCM (autentikasi data)

import base64                            # encoding/decoding base64
import os                                # membuat byte acak untuk IV/key
import io                                # membaca file di memori (tanpa disimpan ke disk)

# ============================================================
# FUNGSI UNTUK MEMBUAT DAN MENGELOLA KEY
# ============================================================

# ----- Generate Key -----
def generate_key():
    """Generate kunci AES 256-bit (32 byte)."""
    return os.urandom(32)

# ----- Wrap Key -----
def wrap_key_with_password(sym_key: bytes, password: str) -> bytes:
    """Bungkus (enkripsi) kunci AES menggunakan password dengan PBKDF2 + AES-GCM."""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    kek = kdf.derive(password.encode())
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    wrapped = aesgcm.encrypt(nonce, sym_key, associated_data=None)
    return salt + nonce + wrapped

# ----- Unwrap Key -----
def unwrap_key_with_password(wrapped_blob: bytes, password: str) -> bytes:
    """Buka kembali key AES dari file .wkey menggunakan password."""
    salt = wrapped_blob[:16]
    nonce = wrapped_blob[16:28]
    wrapped = wrapped_blob[28:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    kek = kdf.derive(password.encode())
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, wrapped, associated_data=None)

# ============================================================
# Fungsi AES-256 CBC Encrypt/Decrypt
# ============================================================

# ENKRIPSI
def aes_encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    """Enkripsi data biner dengan AES-256 CBC."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # IV ditempel di depan ciphertext

# DEKRIPSI
def aes_decrypt_cbc(key: bytes, data: bytes) -> bytes:
    """Dekripsi data biner dengan AES-256 CBC."""
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# ============================================================
# STREAMLIT UI
# ============================================================

st.title("🔐 Aplikasi Kriptografi AES-256 CBC")
st.write("Enkripsi & dekripsi **teks atau file (CSV/XLSX/PDF/Image/Umum)** menggunakan AES-256 CBC dengan fitur *Key Wrapping* (password protected).")

# SIDEBAR: KEY MANAGEMENT
st.sidebar.header("🔑 Manajemen Kunci AES")

if "aes_key" not in st.session_state:
    st.session_state["aes_key"] = generate_key()
key = st.session_state["aes_key"]

if st.sidebar.button("Generate New Key"):
    st.session_state["aes_key"] = generate_key()
    st.sidebar.success("Kunci baru berhasil dibuat!")

st.sidebar.text_area("Current Key (Base64)", base64.b64encode(key).decode())

# ----- Wrap Key -----
st.sidebar.subheader("Wrap Key (Lindungi dengan Password)")
wrap_password = st.sidebar.text_input("Masukkan password untuk wrap key", type="password")
if st.sidebar.button("🔏 Bungkus & Download (.wkey)"):
    if not wrap_password.strip():
        st.sidebar.error("Masukkan password dulu!")
    else:
        wrapped = wrap_key_with_password(key, wrap_password)
        st.sidebar.download_button(
            "💾 Download Wrapped Key",
            wrapped,
            file_name="wrapped_key.wkey",
            mime="application/octet-stream"
        )

# ----- Unwrap Key -----
st.sidebar.subheader("Unwrap Key dari File")
uploaded_wrap = st.sidebar.file_uploader("Upload file .wkey", type=["wkey"])
unwrap_password = st.sidebar.text_input("Masukkan password untuk unwrap key", type="password")
if uploaded_wrap and st.sidebar.button("🔓 Pulihkan Key dari .wkey"):
    try:
        data = uploaded_wrap.read()
        restored_key = unwrap_key_with_password(data, unwrap_password)
        st.session_state["aes_key"] = restored_key
        st.sidebar.success("✅ Key berhasil dipulihkan dan diaktifkan!")
    except Exception as e:
        st.sidebar.error(f"Gagal unwrap key: {e}")

# TAB ENKRIPSI & DEKRIPSI
tab1, tab2 = st.tabs(["🧾 Enkripsi", "📂 Dekripsi"])

# ---------------------- TAB 1: ENKRIPSI ----------------------
with tab1:
    input_type = st.selectbox("Pilih jenis input:", ["Teks", "File Umum (CSV/XLSX/PDF/Image/DLL)"])

    # ======== TEKS ========
    if input_type == "Teks":
        plaintext_input = st.text_area("Masukkan teks untuk dienkripsi:")
        if st.button("🔒 Enkripsi Teks"):
            ciphertext = aes_encrypt_cbc(key, plaintext_input.encode())
            st.text_area("Hasil Enkripsi (Hex):", ciphertext.hex())

    # ======== FILE (semua jenis) ========
    else:
        uploaded_file = st.file_uploader("Upload file untuk dienkripsi", type=None)
        if uploaded_file and st.button("🔒 Enkripsi File"):
            try:
                file_data = uploaded_file.read()
                encrypted_data = aes_encrypt_cbc(key, file_data)
                st.download_button(
                    "💾 Download File Terenkripsi (.bin)",
                    encrypted_data,
                    file_name=f"{uploaded_file.name}.bin",
                    mime="application/octet-stream"
                )
                st.success("✅ File berhasil dienkripsi!")
            except Exception as e:
                st.error(f"Gagal mengenkripsi: {e}")

# ---------------------- TAB 2: DEKRIPSI ----------------------
with tab2:
    input_type2 = st.selectbox("Pilih jenis input terenkripsi:", ["Teks (Hex)", "File .bin (Semua Jenis)"])

    # ======== TEKS ========
    if input_type2 == "Teks (Hex)":
        ciphertext_input = st.text_area("Masukkan ciphertext hex:")
        if st.button("🔓 Dekripsi Teks"):
            try:
                decrypted = aes_decrypt_cbc(key, bytes.fromhex(ciphertext_input))
                st.text_area("Hasil Dekripsi:", decrypted.decode(errors="ignore"))
            except Exception as e:
                st.error(f"Gagal mendekripsi: {e}")

    # ======== FILE ========
    else:
        uploaded_enc = st.file_uploader("Upload file terenkripsi (.bin)", type=["bin"])
        if uploaded_enc and st.button("🔓 Dekripsi File"):
            try:
                decrypted_data = aes_decrypt_cbc(key, uploaded_enc.read())
                st.download_button(
                    "💾 Download File Hasil Dekripsi",
                    decrypted_data,
                    file_name="decrypted_output",
                    mime="application/octet-stream"
                )
                st.success("✅ File berhasil didekripsi! Ganti ekstensi sesuai file asli (misal .pdf, .jpg, .xlsx).")
            except Exception as e:
                st.error(f"Gagal mendekripsi: {e}")

# ============================================================
# CATATAN TAMBAHAN
# ============================================================

st.info("""
### ⚙️ Catatan Proses AES-256 CBC + Key Wrapping:
- AES menggunakan blok **128-bit** dan kunci **256-bit** (32 byte).
- **IV (Initialization Vector)** dibuat acak (16 byte) setiap kali enkripsi.
- Mode **CBC** memastikan pola plaintext tidak muncul pada ciphertext.
- Fitur **Key Wrapping** memungkinkan kunci dibagikan aman dengan password. Pengguna yang tidak memiliki password tidak bisa membuka kunci.
- File terenkripsi disimpan sebagai `.bin`.
- Setelah dekripsi, ubah nama/ekstensi file sesuai jenis aslinya:
  - `.pdf`, `.jpg`, `.png`, `.csv`, `.xlsx`, dll.
- File CSV/XLSX bisa langsung dibuka di Excel setelah didekripsi.
- File gambar atau PDF **tidak bisa ditampilkan langsung di Streamlit**, tapi bisa disimpan dan dibuka manual setelah didekripsi.
""")
