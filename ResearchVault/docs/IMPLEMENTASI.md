# Catatan implementasi versi 2

Perubahan terbaru dan format RVTXT2 dijelaskan pada `UPGRADE_V2.md`. Catatan berikut merupakan arsip rancangan versi 1: pembatasan satu akun serta enkripsi teks dua tahap sudah digantikan pada versi 2.

# Catatan implementasi terhadap rancangan

Implementasi mengikuti platform, palet, algoritma dan cakupan lokal satu akun pada rancangan yang dilampirkan. Beberapa keputusan teknis disederhanakan secara eksplisit:

| Bagian rancangan | Implementasi 1.0 dan alasan |
|---|---|
| File key store terpisah | Key store tetap dibungkus password + DPAPI, tetapi disimpan sebagai BLOB di tabel users. Rotasi hash password dan key store menjadi satu transaksi SQLite; backup tidak berisiko memisahkan versi keduanya. |
| Banyak package service/repository | Dipadatkan menjadi engine, database, crypto, storage, stego, adapter Windows dan UI. Guard tetap berada pada service, terpisah dari tombol GUI. |
| Sepuluh layar | Registrasi/login dalam layar akses; tujuh area kerja. Profil dan keamanan digabung; tidak ada layar splash tersendiri. |
| Tabel research_assets dan blocks terpisah | Identitas aset, alias snapshot dan hash berada dalam payload blok canonical. Setiap registrasi membuat asset ID baru. Pengelompokan versi aset logis yang sama belum disediakan. |
| Tabel histori file dan stego terpisah | Digabung ke artifacts dengan discriminator kind. Audit tetap hanya metadata. |
| Nama asli file di payload | Tidak disimpan pada v1. Pengguna menentukan nama/ekstensi saat dekripsi; bytes file tetap identik. |
| Pilihan timeout | Versi ini menetapkan 5 menit; tidak menyediakan pengaturan untuk melemahkan autentikasi. |
| Ekspor menimpa dengan konfirmasi | Semua output wajib nama baru; no-replace atomik. |
| Status biometrik | Adapter memakai IUserConsentVerifierInterop dengan HWND. Berhasil berarti Windows Hello terverifikasi, bukan bukti khusus sidik jari. |
| Serial USB | Fingerprint SHA-256 dari serial disk, PnP ID dan serial volume. Drive letter tidak masuk fingerprint. Perubahan volume/format USB membatalkan kecocokan. |
| Dependensi terkunci | Versi Python library inti yang tersedia dan diuji dicatat dalam requirements. pywin32 dan PyInstaller memiliki rentang; versi Windows final harus dicatat setelah penerimaan hardware. |

## Format dan keamanan

Envelope biner: magic `RVF1`, panjang header unsigned 4 byte big-endian, header JSON canonical, ciphertext+tag. Header memuat versi, jenis, algoritma, profil KDF allowlist, salt 16 byte, nonce 12 byte, dan panjang ciphertext. Byte header aktual digunakan sebagai AAD. Teks membungkus envelope AES pada `RVTXT1:` + Base64; stego membungkus envelope AES pada `RVST1` + panjang 8 byte, lalu menyisipkan bit MSB-first ke RGB. File memakai ChaCha20-Poly1305.

Argon2id KDF: memory 65536 KiB, time 3, parallelism 4, output 32 byte. Master key random 32 byte dibungkus AES-GCM dengan KEK dari password, lalu DPAPI user-scope. Hash password bukan kunci enkripsi. HKDF-SHA256 menurunkan kunci catatan dengan konteks `researchvault/notes/v1`.

Catatan memiliki nonce acak 12 byte, revision, dan AAD identitas user/note/revision. UNIQUE(user_id, nonce) menolak duplikasi nonce di baris aktif; service mencoba nonce baru. Rollback database lengkap dan rekonstruksi chain konsisten masih mungkin oleh penguasa semua data.

Pemeriksaan USB dilakukan di service sebelum operasi dan sebelum commit, serta timer UI sekitar 3 detik. Operasi berat dan monitor berada pada worker. Generation sesi membatalkan hasil dari sesi lama. Perlindungan ini tidak menjanjikan penghapusan sempurna seluruh salinan plaintext dari RAM Python.

## Sumber API

- Microsoft: https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.ui.userconsentverifier
- Desktop HWND interop: https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync
- DPAPI: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- cryptography AEAD: https://cryptography.io/en/latest/hazmat/primitives/aead/
- Argon2: https://argon2-cffi.readthedocs.io/en/stable/api.html
- SQLite foreign keys: https://www.sqlite.org/foreignkeys.html

Dokumentasi API bukan bukti bahwa build Windows atau sensor telah diuji. Lihat hasil aktual dan checklist penerimaan.
