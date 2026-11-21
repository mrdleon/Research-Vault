# ResearchVault 2.1 — Perbaikan pemulihan file

## Penyebab yang ditemukan di kode

Versi sebelumnya mengembalikan bytes hasil dekripsi tetapi tidak menyimpan nama dan ekstensi file asli. Default tujuan dekripsi adalah `dokumen-hasil` tanpa ekstensi, dan kolom tujuan tidak dibersihkan ketika mode berubah. Akibatnya, file PDF yang isinya benar bisa tersimpan tanpa `.pdf` atau masih bernama `.rvault`, sehingga Windows tidak mengenalinya dengan benar.

Belum ada pasangan file asli dan file gagal milik pengguna yang diperiksa. Temuan ini menjelaskan kelemahan kode yang telah diperbaiki; jika file sumber terenkripsi sudah rusak atau passphrase berbeda, dekripsi harus ditolak, bukan dipaksakan menghasilkan file.

## Memasang pembaruan

1. Tutup ResearchVault dan DB Browser for SQLite. Cadangkan folder proyek serta data `%LOCALAPPDATA%\ResearchVault`.
2. Ekstrak ZIP. Salin **seluruh isi folder ResearchVault** dari ZIP ke folder proyek lama yang berisi `START.bat` dan `main.py`. Setujui penggantian kode. Jangan menyalinnya ke AppData dan jangan menumpuk menjadi `ResearchVault\ResearchVault`.
3. Jangan menghapus `.venv`, `native\researchvault_hello.dll`, `vault.db`, maupun `ResearchVault.token`. ZIP tidak berisi database pengguna atau token.
4. Jalankan `START.bat` dari folder yang sudah diperbarui. Jika memakai EXE, jalankan `BUILD_EXE.bat` dahulu dan gunakan hasil build baru; EXE lama tidak berubah hanya dengan menyalin kode Python.

Paket lengkap ini mempertahankan registrasi/login dan enkripsi teks empat tahap versi 2. Perbaikan 2.1 tidak mengubah skema database v2. Jika berangkat dari aplikasi v1, migrasi akun yang sudah ada pada versi 2 tetap berlaku; baca juga BACA_DULU_UPGRADE.md.

## File yang dienkripsi mulai versi 2.1

Contoh: `Laporan Penelitian.pdf`.

1. Mode Enkripsi: pilih PDF asli, pilih hasil enkripsi, isi passphrase dan konfirmasi, lalu Proses file.
2. Aplikasi menyimpan nama file, ukuran, SHA-256 dan bytes asli dalam paket terenkripsi ChaCha20-Poly1305. Nama tidak disimpan terbuka di header.
3. Mode Dekripsi: pilih `.rvault`, klik **Pilih folder hasil**, masukkan passphrase yang sama, lalu Proses file. Kolom Ekstensi file lama boleh dikosongkan.
4. Hasil otomatis bernama `Laporan Penelitian.pdf` dan status menampilkan lokasi lengkapnya. Buka file di lokasi tersebut, bukan file `.rvault`.
5. Bila nama itu sudah ada, aplikasi membuat nama seperti `Laporan Penelitian (dipulihkan 1).pdf`. File asli tidak ditimpa.

File terenkripsi boleh diubah namanya atau dipindah folder; nama aslinya tetap berasal dari metadata terenkripsi. Tidak perlu mempertahankan salinan file asli agar dapat mendekripsi.

## File yang sudah terenkripsi sebelum versi 2.1

File lama tetap dapat dibuka dengan passphrase lamanya. Informasi nama/ekstensi yang dahulu tidak disimpan tidak dapat dipulihkan secara pasti hanya dari ciphertext.

- Jika file bernama `laporan.pdf.rvault`, aplikasi memakai `laporan.pdf` sebagai petunjuk nama. Pastikan petunjuk tersebut memang sesuai sumber dahulu.
- Jika file bernama `dokumen.rvault`, pilih folder hasil, lalu isi **Ekstensi file lama** dengan `.pdf`, `.docx`, `.xlsx`, `.png`, atau ekstensi sumber yang benar. Contoh hasil: `dokumen.pdf`.
- Jika petunjuk nama file lama salah, isi kolom ekstensi untuk menggantinya.
- Untuk file lama yang aslinya memang tanpa ekstensi, kolom lokasi hasil dapat diisi path lengkap baru, misalnya `C:\Users\ASUS\Documents\hasil_tanpa_ekstensi`, bukan folder saja.
- Jangan memilih ekstensi berdasarkan tebakan atau sekadar mengganti `.rvault` menjadi `.pdf` sebelum dekripsi. Mengganti nama ciphertext bukan mendekripsi isi.

Enkripsi baru memakai varian payload `file-v2`; dekripsinya memerlukan ResearchVault 2.1. Aplikasi 2.1 dapat membaca varian lama `file`. File, teks, catatan, dan gambar terenkripsi lama tidak perlu dikonversi untuk digunakan kembali.

## Apa yang dijamin dan diperiksa

- Bytes isi dipulihkan tanpa konversi teks, kompresi ulang gambar, atau perubahan newline.
- Untuk format baru, ukuran dan SHA-256 bytes hasil dibandingkan dengan metadata asli setelah autentikasi ChaCha20-Poly1305 berhasil.
- Nama/path berbahaya dari metadata ditolak; metadata hanya boleh memberi nama file, bukan folder tujuan.
- Salah passphrase, ciphertext rusak, metadata tidak valid, atau hash tidak cocok tidak menghasilkan file plaintext baru.
- File sumber tidak diubah; file tujuan yang sudah ada tidak ditimpa. Jika lokasi tujuan eksplisit memiliki ekstensi yang salah untuk format baru, aplikasi meminta ekstensi yang sesuai.
- Timestamp pembuatan/modifikasi, izin filesystem, serta alternate data streams Windows tidak direstorasi. Kesamaan yang diuji adalah **isi file**, bukan semua atribut filesystem.

## Uji singkat setelah pemasangan

1. Pilih satu PDF, DOCX, dan PNG yang bisa dibuka sebelum enkripsi.
2. Enkripsi masing-masing. Dekripsi ke folder kosong menggunakan versi 2.1.
3. Periksa nama/ekstensi hasil dan buka dengan aplikasi yang sesuai.
4. Bandingkan SHA-256 file asli dan hasil jika diperlukan, misalnya PowerShell: `Get-FileHash -Algorithm SHA256 "C:\lokasi\file.pdf"`.
5. Hash harus sama. Jika masih berbeda atau tidak bisa dibuka, simpan file asli, `.rvault`, hasil, dan pesan error untuk pemeriksaan; jangan menimpa file asli.

131 tes otomatis lulus di Linux dengan adapter hardware tiruan. UI diperiksa pada 1024×720. USB fisik, Windows Hello, DPAPI, serta EXE tetap memerlukan pengujian laptop Windows. ZIP berisi source lengkap, bukan EXE/DLL terkompilasi.
