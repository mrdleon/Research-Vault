> Catatan historis versi 2.0. Versi 2.1 menambah varian payload file-v2 untuk metadata nama/ukuran/hash; pembaca file lama tetap tersedia. Lihat BACA_DULU_FIX_DEKRIPSI.md.

# Catatan teknis ResearchVault 2.0

## Perubahan akun dan antarmuka

`ui.py` menyimpan pilihan `access_registration` secara eksplisit. Pilihan ini tidak lagi diputuskan hanya oleh ada/tidaknya akun. Registrasi sukses memilih Login, mempertahankan username untuk kemudahan masuk, serta menghapus password, nama tampilan sementara, dan daftar USB dari formulir.

`Engine.register()` mengizinkan akun baru hanya ketika vault terkunci, memeriksa username unik sebelum operasi perangkat serta di dalam transaksi tulis, dan tetap mensyaratkan USB kosong, Windows Hello, hash Argon2id, serta DPAPI. Setiap akun memperoleh master key, token, dan GENESIS tersendiri. Tidak ada faktor autentikasi yang dilewati.

Database v2 menghapus UNIQUE pada `users.windows_sid` agar beberapa akun aplikasi dapat terikat pada satu akun Windows. UNIQUE username, semua foreign key, ID pemilik, serta pemeriksaan SID saat login/sesi dipertahankan. Migrasi menggunakan backup SQLite yang konsisten, transaksi `BEGIN IMMEDIATE`, tabel pengguna pengganti, pemeriksaan foreign key, commit atau rollback. Payload, ID, hash, key store, dan token lama tidak dihitung ulang.

Pemisahan data oleh `user_id` adalah kontrol aplikasi. Beberapa akun pada SID yang sama bukan isolasi akun sistem operasi. Windows Hello memverifikasi pemilik sesi Windows, bukan username ResearchVault secara mandiri. DPAPI tetap user-scope pada Windows; akun aplikasi baru tidak membuat identitas Windows baru.

## Urutan enkripsi dan kunci

1. Validasi UTF-8 maksimum 64 KiB, shift integer 1–25, kunci Vigenère ASCII A–Z dan passphrase 12–1024 karakter.
2. Caesar mempertahankan case serta non-ASCII; Vigenère memproses keluaran Caesar.
3. Buat payload JSON `{text, commitment}`. Commitment SHA-256 domain khusus mencakup kunci Vigenère ternormalisasi dan shift Caesar, sehingga kombinasi salah yang kebetulan menghasilkan pergeseran sama tetap ditolak. Commitment berada **di dalam** kedua enkripsi modern.
4. Buat salt acak 16 byte, nonce AES 12 byte, serta nonce ChaCha 12 byte.
5. Argon2id m=65536 KiB, t=3, p=4 menurunkan root key 32 byte dari passphrase dan salt. HKDF-SHA256 dengan label terpisah `ResearchVault/RVTXT2/AES-256-GCM` serta `ResearchVault/RVTXT2/CHACHA20-POLY1305` menghasilkan dua key 32 byte yang berbeda.
6. AES-256-GCM mengenkripsi JSON. AAD adalah `RVTXT2/AES/` + bytes header aktual. Tag 16 byte mengikuti ciphertext AES.
7. ChaCha20-Poly1305 mengenkripsi **seluruh ciphertext AES beserta tag AES**, dengan AAD `RVTXT2/CHACHA/` + header yang sama. Tag luar 16 byte mengikuti ciphertext ChaCha.
8. Paket biner dibungkus Base64 dengan awalan `RVTXT2:`.

Dekripsi memvalidasi struktur dan profil sebelum KDF, membuka lapisan ChaCha, membuka lapisan AES, memverifikasi commitment kunci klasik, lalu membalik Vigenère dan Caesar. Tidak ada fallback dari RVTXT2 gagal autentikasi ke format lama. Nonce dan salt baru dibuat per pesan. Kunci kedua algoritma modern tidak digunakan ulang sebagai satu key bersama.

## Format RVTXT2

`RVTXT2:` + Base64 dari:

| Bagian | Isi |
|---|---|
| Magic 4 byte | RVT2 |
| Panjang header 4 byte | Unsigned big-endian, 1–2048 byte |
| Header UTF-8 | JSON canonical dengan v, kind, pipeline, kdf, keys, salt, aes_nonce, chacha_nonce, length |
| Ciphertext luar | Keluaran ChaCha20-Poly1305 termasuk tag |

`v=2`, `kind=text`, pipeline wajib berurutan `[CAESAR, VIGENERE, AES-256-GCM, CHACHA20-POLY1305]`, kdf `argon2id-m65536-t3-p4`, keys `HKDF-SHA256-RVTXT2`. Length menghitung ciphertext luar beserta tag; nilainya panjang JSON payload ditambah 32 byte (dua tag). Header tidak menyimpan shift atau kunci klasik/passphrase. Header bukan rahasia tetapi diikat oleh AAD kedua lapisan.

Parser menolak field tambahan/hilang/duplikat, versi/urutan/profil tak dikenal, panjang yang tidak cocok, salt/nonce salah ukuran, dan input berlebihan. Batas transport teks tetap 10 × MAX_TEXT untuk mengakomodasi ekspansi JSON serta Base64. `text_io.py` menangani UTF-8/BOM/newline dan validasi struktur; autentikasi menunggu dekripsi.

RVTXT1 memakai jalur pembaca lama. Format RVF1 untuk file, key store, dan stego tidak berubah. Algoritma file dan catatan aman tidak diubah. `Engine.text(..., decrypt=False, shift=3)` mempertahankan urutan parameter lama dan menambahkan shift sebagai parameter terakhir.

## Berkas utama yang berubah

| Berkas | Perubahan |
|---|---|
| researchvault/crypto.py | Caesar, format RVTXT2, key derivation terpisah, dua lapisan AEAD, pembaca legacy |
| researchvault/text_io.py | Impor/ekspor struktur RVTXT1 dan RVTXT2 |
| researchvault/engine.py | Registrasi beberapa akun, penerusan shift Caesar |
| researchvault/database.py | Skema v2, backup otomatis dan migrasi |
| researchvault/ui.py | Pilihan akses, input Caesar, instruksi format baru dan impor |
| researchvault/__init__.py | Versi 2.0.0 |
| tests/test_upgrade_v2.py | Algoritma, kompatibilitas, autentikasi, akun, migrasi dan UI |
| tests/fixtures/legacy_rvtxt1.txt | Ciphertext uji yang dibuat memakai crypto.py asli versi 1 |
| tests/test_text_io.py dan test_ui.py | Ekspektasi output baru dan roundtrip UI dengan Caesar bukan default |

## Referensi implementasi

- PyCA Cryptography, authenticated encryption: https://cryptography.io/en/stable/hazmat/primitives/aead/
- PyCA Cryptography, key derivation: https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/
- Parameter Argon2id mengikuti implementasi ResearchVault sebelumnya; tidak mengubah profil KDF file, key store, atau payload lama.

Ini format pendidikan khusus ResearchVault, bukan standar interoperabilitas eksternal dan bukan hasil audit kriptografi independen.
