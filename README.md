# Keamanan-Data: AES-256
## Deskripsi Singkat
Proyek ini merupakan implementasi algoritme AES-256 dalam mode CBC (Cipher Block Chaining) yang dikembangkan menggunakan Python dan framework Streamlit. Aplikasi ini memungkinkan pengguna melakukan enkripsi dan dekripsi teks maupun berbagai jenis file (CSV, Excel, PDF, gambar, dan lainnya). Selain itu, aplikasi ini memiliki fitur Key Wrapping (pelindung kunci) menggunakan password agar kunci enkripsi dapat disimpan dan dibagikan dengan aman.

## Fitur
1. Enkripsi dan dekripsi teks atau file menggunakan AES-256 dalam mode CBC.
2. Fitur Key Wrapping menggunakan PBKDF2 dan AES-GCM untuk melindungi kunci dengan password.
3. Dapat memulihkan kunci dari file .wkey dengan password yang benar.
4. Menyimpan nama file asli di dalam hasil enkripsi agar otomatis dikembalikan saat dekripsi.
5. Mendukung berbagai format file seperti .csv, .xlsx, .pdf, .jpg, .png, dan format umum lainnya.
6. Antarmuka interaktif menggunakan Streamlit yang mudah digunakan.

## Persyaratan
- Python 3.8 atau versi yang lebih baru
- Pustaka: ```pip install streamlit cryptography pandas```

## Cara Menjalankan
1. Clone repositori ini:

   ```git clone https://github.com/<username>/aes256-cbc-app.git```
   
   ```cd aes256-cbc-app```
2. Instal dependensi: ```pip install streamlit cryptography pandas```
3. Jalankan aplikasi streamlit: ```streamlit run aes256_cbc_app.py```
4. Buka browser dan akses: ```http://localhost:8501```

## Cara Penggunaan
### Manajemen Kunci
- Gunakan tombol Generate New Key untuk membuat kunci AES baru berukuran 256-bit.
- Gunakan fitur Wrap Key untuk membungkus (melindungi) kunci dengan password dan simpan sebagai file ```.wkey```.
- Gunakan Unwrap Key untuk memulihkan kunci dari file ```.wkey``` dengan password yang sesuai.

### Enkripsi
- Pilih tab Enkripsi.
- Pilih jenis input (teks atau file).
- Klik tombol Enkripsi untuk menghasilkan ciphertext.
- Unduh hasil enkripsi dalam format ```.bin```.

### Dekripsi
- Pilih tab Dekripsi.
- Masukkan ciphertext dalam format hex atau unggah file ```.bin```.
- Klik tombol Dekripsi untuk mengembalikan hasil ke bentuk plaintext atau file asli.

## Catatan Teknis
- Panjang kunci AES adalah 256 bit (32 byte).
- Panjang blok AES adalah 128 bit (16 byte).
- IV (Initialization Vector) dihasilkan secara acak setiap proses enkripsi.
- Mode CBC digunakan agar pola data asli tidak muncul dalam ciphertext.
- Proses Key Wrapping menggunakan PBKDF2-HMAC-SHA256 dan AES-GCM untuk keamanan tambahan.
- File hasil enkripsi menyimpan metadata nama file asli untuk pemulihan otomatis saat dekripsi.
