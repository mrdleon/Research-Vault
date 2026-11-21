> Pembaruan 2.1: baca BACA_DULU_FIX_DEKRIPSI.md terlebih dahulu untuk pemulihan nama dan ekstensi file. Panduan berikut menjelaskan upgrade akun dan teks versi 2 yang tetap berlaku.

# ResearchVault 2.0 — Registrasi dan enkripsi teks empat tahap

Paket ini berisi aplikasi desktop Windows beserta kode sumber lengkap, pengujian, dan panduan. Paket belum berisi EXE/DLL hasil kompilasi Windows. Perbaikan hashing aset serta fitur ekspor–impor TXT dari pembaruan sebelumnya sudah disertakan.

## Memasang ke proyek yang sudah berjalan

1. Tutup ResearchVault, termasuk EXE lama, serta DB Browser for SQLite.
2. Simpan salinan folder proyek lama. Cadangkan data melalui fitur Backup sebelum menutup aplikasi, atau salin folder `%LOCALAPPDATA%\ResearchVault` setelah semua aplikasi yang membuka database ditutup.
3. Ekstrak ZIP ini. Salin **seluruh isi folder `ResearchVault` di dalam ZIP** ke folder proyek ResearchVault lama dan setujui penggantian file kode. Yang dimaksud adalah folder berisi `START.bat` dan `main.py`, bukan folder data di AppData. Jangan menumpuk menjadi `ResearchVault\ResearchVault`.
4. Folder `.venv` serta DLL `native\researchvault_hello.dll` yang sudah ada tetap dipakai. ZIP ini tidak menyertakan atau mengganti keduanya. Jangan menghapus `vault.db` maupun `ResearchVault.token`.
5. Jalankan **START.bat dari folder proyek yang sudah diperbarui**. Jika memakai shortcut EXE lama, perubahan belum akan terlihat. Jalankan `BUILD_EXE.bat` untuk menghasilkan EXE versi baru, kemudian gunakan seluruh folder `dist\ResearchVault` hasil build baru.
6. Saat pertama kali membuka database versi 1, aplikasi membuat cadangan `vault-before-v2-<id>.db` di folder data, lalu memigrasikan database. Akun, password, token, catatan, dan rantai aset lama dipertahankan. Jika migrasi gagal, transaksi dibatalkan; jangan menghapus database untuk mengatasinya.
7. Login menggunakan akun serta dongle lama untuk memeriksa catatan dan aset. Lalu lakukan skenario di bawah.

Jika instalasi benar-benar baru, ikuti `README.md`: pasang Python/Build Tools, siapkan Windows Hello, jalankan `INSTALL.bat`, kemudian `START.bat`.

## 1 Pilihan Registrasi dan Login

Di halaman awal selalu tersedia dua tombol:

- **Sudah punya akun · Login**: masukkan username dan password, hubungkan dongle akun tersebut, lalu selesaikan Windows Hello.
- **Belum punya akun · Registrasi**: isi username unik, nama tampilan, password dan konfirmasinya. Klik Cari USB, pilih flashdisk tanpa token ResearchVault, kemudian Daftarkan akun dan dongle. Setelah berhasil, formulir kembali ke Login dan password dibersihkan.

Registrasi dapat dilakukan walaupun sudah ada akun dalam database. Setiap akun mempunyai master key, catatan, rantai aset, dan dongle sendiri. Untuk mendaftarkan akun lain dari sesi yang masih terbuka, klik **Kunci vault** terlebih dahulu.

**Gunakan USB lain untuk akun baru.** Versi ini mempertahankan satu file `ResearchVault.token` per USB, sehingga satu USB yang sudah berisi token tidak ditimpa atau dipakai sebagai dongle akun lain. Jangan menghapus token akun lama agar bisa mendaftarkan akun baru.

Username 3–40 karakter: huruf ASCII kecil, angka, titik, garis bawah, atau tanda minus. Huruf besar dinormalisasi menjadi kecil. Password 12–1024 karakter. Username yang sama ditolak.

Beberapa akun aplikasi pada satu akun Windows tetap menggunakan konteks Windows Hello dan DPAPI akun Windows yang sama. Ini tidak membuat profil sidik jari Windows baru untuk setiap username ResearchVault. Untuk akun Windows yang berbeda, lokasi LOCALAPPDATA dan perlindungan DPAPI juga berbeda.

## 2 Enkripsi teks baru

Urutan enkripsi: **Caesar → Vigenère → AES-256-GCM → ChaCha20-Poly1305**.

Urutan dekripsi: **ChaCha20-Poly1305 → AES-256-GCM → Vigenère → Caesar**.

Contoh untuk demonstrasi saja:

| Isian | Contoh |
|---|---|
| Mode | Enkripsi pesan |
| Pesan | Penelitian air: jumlah sampel 10 🌱 |
| Caesar | 3 |
| Kunci Vigenère | LEMON |
| Passphrase AES + ChaCha20 | Latihan-Riset-2026! |
| Konfirmasi passphrase | Latihan-Riset-2026! |

Klik **Proses teks**. Hasil dimulai dengan `RVTXT2:`. Pilih **Ekspor hasil enkripsi** untuk menyimpan `.txt`.

Untuk membukanya kembali:

1. Klik Bersihkan, lalu **Impor teks terenkripsi** dan pilih TXT tadi.
2. Mode otomatis menjadi Dekripsi. Angka Caesar direset ke 3, sementara kolom kunci/passphrase dikosongkan. Masukkan kembali **angka Caesar asli**, termasuk jika sebelumnya bukan 3.
3. Masukkan kunci Vigenère dan passphrase yang sama, kemudian Proses teks.
4. Pesan asli ditampilkan jika kedua tag autentikasi serta pasangan kunci klasik cocok. Jika salah, hasil tidak ditampilkan.

Simpan angka Caesar, kunci Vigenère, dan passphrase secara terpisah dari file ciphertext. File TXT tidak menyimpan ketiganya secara terbuka. Satu passphrase diolah menjadi **dua kunci kriptografi berbeda**, sehingga pengguna tidak perlu mengisi dua passphrase modern.

Caesar menerima angka 1–25; Vigenère menerima A–Z tanpa spasi. Kedua algoritma klasik menggeser huruf ASCII saja, menjaga huruf besar/kecil. Emoji, aksara lain, angka, spasi, dan tanda baca dipertahankan; semua teks tetap dilindungi kedua lapisan modern. Batas input 64 KiB UTF-8.

## 3 Hasil teks versi lama

File `RVTXT1:` yang dibuat versi sebelumnya tetap dapat diimpor dan didekripsi memakai kunci Vigenère dan passphrase AES lamanya. Angka Caesar diabaikan untuk RVTXT1. Enkripsi baru selalu menghasilkan RVTXT2. Aplikasi lama tidak dapat membaca RVTXT2; gunakan aplikasi versi 2 untuk dekripsi.

Impor hanya memeriksa struktur, bukan membuktikan keaslian atau kebenaran kunci. Pemeriksaan autentikasi dilakukan ketika **Proses teks** menjalankan dekripsi. Hasil enkripsi teks tidak otomatis disimpan dalam database; ekspor TXT dilakukan secara eksplisit.

## 4 Skenario uji di laptop

| Skenario | Hasil yang diharapkan |
|---|---|
| Login akun lama setelah upgrade | Catatan dan aset lama tetap tersedia |
| Pilih Registrasi saat akun lama sudah ada | Form registrasi dapat dibuka |
| Registrasi username baru dengan USB lain | Berhasil; kembali ke halaman Login |
| Registrasi username yang sama | Ditolak tanpa mengganti akun/token lama |
| Registrasi memakai USB bertoken lama | Ditolak; token lama tidak ditimpa |
| Login akun kedua | Catatan kosong dan hanya blok GENESIS; data akun pertama tidak tampil |
| Enkripsi, ekspor, tutup aplikasi, login, impor, dekripsi | Pesan kembali identik dengan input yang benar |
| Ubah Caesar dari 3 ke 4 saat dekripsi RVTXT2 | Ditolak |
| Ubah kunci Vigenère atau passphrase | Ditolak |
| Ubah karakter ciphertext atau header | Impor/dekripsi ditolak sesuai jenis kerusakan |
| Impor RVTXT1 lama dengan kunci lama | Berhasil; Caesar tidak dipakai |
| Windows Hello dibatalkan atau dongle tidak cocok | Akses ditolak |

## Batas yang perlu diketahui

- Pengujian otomatis memakai adapter perangkat tiruan di Linux. Windows Hello, DPAPI, USB fisik, notifikasi Windows, dan EXE tetap perlu diuji pada laptop Windows. Adapter tiruan hanya ada dalam folder tes; aplikasi produksi tetap memakai adapter Windows.
- Cadangan sebelum migrasi dan fitur Backup berisi **seluruh database**, bukan satu akun. Simpan dengan perlindungan yang sama seperti vault. Pemulihan ke cadangan lama mengembalikan keadaan seluruh akun pada waktu cadangan dibuat.
- Jangan membuka database v2 dengan aplikasi v1. Untuk kembali ke v1, tutup semua aplikasi dan pulihkan cadangan v1 secara sengaja; perubahan sesudah cadangan tidak ikut kembali.
- Caesar dan Vigenère adalah algoritma klasik untuk pembelajaran. Empat tahap tidak berarti empat kali lebih aman. Kekuatan perlindungan modern tetap bergantung pada passphrase, kunci, nonce, library, dan lingkungan komputer.
- Fitur file tetap memakai ChaCha20-Poly1305, sedangkan teks memakai empat tahap yang juga mencakup algoritma tersebut. Untuk menjelaskan tugas, sebutkan perbedaan pipeline; jangan mengatakan algoritma modern teks dan file sepenuhnya berbeda.
