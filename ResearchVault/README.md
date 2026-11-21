# ResearchVault 2.1

Aplikasi desktop untuk pengamanan dokumen dan data penelitian mahasiswa.
Target: **Windows 11 x64 · Python 3.12 · PySide6 · SQLite**.

Paket ini berisi **kode aplikasi yang telah diuji pada tingkat modul dan antarmuka**, bukan sekadar rancangan atau halaman contoh. Paket belum menyertakan EXE/DLL Windows yang sudah dikompilasi. Adapter Windows Hello harus dibangun di Windows menggunakan skrip yang disediakan. Hardware Windows Hello, USB fisik, DPAPI, WMI dan paket EXE **belum diuji pada mesin Windows nyata** dalam pengerjaan ini. Jangan menyatakan tujuh kriteria tugas sudah lulus penerimaan hardware sebelum menguji di laptop tim.

## Perbaikan dekripsi file versi 2.1

Baca **BACA_DULU_FIX_DEKRIPSI.md**. Enkripsi file baru menyimpan nama, ukuran, dan SHA-256 dalam payload terenkripsi. Dekripsi ke folder memulihkan nama serta ekstensi otomatis. Berkas lama tetap didukung dengan ekstensi manual bila diperlukan.

## Upgrade dari versi sebelumnya

Baca **BACA_DULU_UPGRADE.md** terlebih dahulu. Versi 2 menambah pilihan Registrasi/Login, beberapa akun lokal, serta enkripsi teks empat tahap berformat RVTXT2. File RVTXT1 lama tetap dapat didekripsi. Database v1 dicadangkan otomatis lalu dimigrasikan ke v2.

## Mulai di Windows

1. Ekstrak seluruh ZIP ke folder lokal, misalnya `D:\ResearchVault`. Jangan menjalankan langsung di dalam ZIP.
2. Pasang **Python 3.12 x64** dari https://www.python.org/downloads/windows/. Pastikan `py -3.12 --version` berfungsi. Python launcher dibutuhkan oleh skrip instalasi.
3. Untuk membangun adapter Hello satu kali, pasang **Visual Studio Build Tools 2022 atau lebih baru**, pilih workload **Desktop development with C++**, MSVC x64, dan **Windows 11 SDK 10.0.22621 atau lebih baru**. Unduh dari https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022 . Ini compiler, bukan aplikasi Visual Studio Code.
4. Atur Windows Hello di **Settings → Accounts → Sign-in options**. Untuk demonstrasi biometrik, daftarkan sidik jari atau wajah melalui sensor kompatibel.
5. Klik dua kali **`INSTALL.bat`**. Skrip membuat `.venv`, memasang dependency, dan membangun `native/researchvault_hello.dll`. Internet hanya diperlukan untuk instalasi dependency. Tidak perlu menjalankan sebagai Administrator setelah alat terpasang.
6. Klik dua kali **`START.bat`**.
7. Hubungkan USB flashdisk yang memiliki serial dan identitas perangkat yang dapat dibaca. Pada registrasi, klik **Cari USB**, pilih perangkat, isi akun dan password minimal 12 karakter, lalu verifikasi Windows Hello.
8. Registrasi menghasilkan `ResearchVault.token` pada USB. **Jangan hapus atau ubah token**. Selanjutnya login dengan USB tersebut tetap terhubung, Windows Hello, dan password akun.

Tidak ada password bawaan, akun demo, atau tombol lewati autentikasi di aplikasi. Test double hanya berada di direktori `tests/`; aplikasi tidak mengimpornya.

## Isi paket

| Lokasi | Isi |
|---|---|
| `main.py` | Entry point dan pencegahan dua instance |
| `researchvault/ui.py` | Antarmuka Indonesia, navigasi, worker, lock dan pembersihan tampilan |
| `researchvault/engine.py` | Registrasi, login, sesi, seluruh service dan transaksi |
| `researchvault/crypto.py` | Argon2id, HKDF, Caesar, Vigenère, AES-GCM, ChaCha20-Poly1305 dan envelope |
| `researchvault/platform_windows.py` | SID, DPAPI, pemetaan USB WMI dan pemanggilan DLL Hello |
| `researchvault/stego.py` | Penyisipan/ekstraksi LSB RGB pada PNG |
| `researchvault/database.py` | Skema dan koneksi SQLite per operasi/thread |
| `researchvault/storage.py` | Baca berbatas, hash streaming, ekspor atomik tanpa menimpa |
| `native/hello.cpp` | Adapter C++/WinRT desktop HWND untuk Windows Hello |
| `tests/` | Pengujian otomatis; hardware tiruan hanya untuk pengujian |
| `examples/` | Data dummy untuk mencoba fitur setelah login |
| `docs/` | Petunjuk fitur, perbedaan implementasi, hasil uji dan checklist hardware |

## Fitur yang tersedia

- Pilihan Registrasi/Login dan beberapa akun lokal dengan username unik. Tiap akun memiliki master key, catatan, rantai aset, dan dongle sendiri. SID Windows tetap diperiksa; Argon2id untuk hash password.
- Login wajib dongle, Windows Hello, password; key store dibungkus dengan kunci turunan password dan DPAPI user-scope.
- Enkripsi teks Caesar → Vigenère → AES-256-GCM → ChaCha20-Poly1305, format `RVTXT2:`. Verifikasi angka Caesar dan kunci Vigenère saat dekripsi. Ekspor/impor TXT serta dekripsi RVTXT1 lama didukung.
- Enkripsi file ChaCha20-Poly1305 menjadi `.rvault`, maksimum 25 MiB; sumber tidak ditimpa.
- Tambah, baca, cari judul, edit, dan hapus catatan dengan judul/isi terenkripsi di SQLite.
- Penyisipan pesan AES-GCM pada LSB RGB PNG; RGB/RGBA didukung, alpha tetap utuh.
- Pendaftaran aset, validasi rantai SHA-256, dan verifikasi file pembanding secara terpisah.
- Dongle cadangan, pencabutan dongle, ganti password, profil, backup konsisten, metadata audit.
- Kunci manual, timeout lima menit, pemeriksaan USB berkala, penolakan hasil worker dari sesi lama, respons terhadap Windows session lock.

## Membuat EXE

Setelah `START.bat` dan hardware terbukti bekerja di laptop, jalankan **`BUILD_EXE.bat`**. Skrip membangun DLL, memasang alat pengujian, menjalankan test suite, dan membuat paket dengan PyInstaller.

Hasil: `dist\ResearchVault\ResearchVault.exe`. Distribusikan **seluruh folder** `dist\ResearchVault`, bukan hanya EXE. Penerima paket hasil build tidak perlu compiler/Python, tetapi mungkin memerlukan Microsoft Visual C++ Redistributable x64. Pengujian EXE di komputer tujuan tetap diperlukan; executable belum ditandatangani digital.

## Data, backup, dan pemulihan

Data runtime disimpan di `%LOCALAPPDATA%\ResearchVault\vault.db`. Key store DPAPI berada sebagai BLOB di database agar perubahan password dan pembungkusan kunci dapat dilakukan dalam **satu transaksi atomik**. Tidak ada file kunci terpisah yang harus dipasangkan.

Gunakan **Keamanan & profil → Backup vault**, kemudian masukkan password dan verifikasi Hello. Cadangan berisi database konsisten beserta key store terlindungi untuk seluruh akun dalam database. Backup/restore berlaku untuk seluruh vault, bukan satu akun saja. Ekspor `.rvault` dan PNG berada di folder pilihan pengguna, sehingga perlu dicadangkan terpisah.

Untuk restore pada komputer dan akun Windows yang sama: tutup aplikasi; simpan salinan `vault.db` sekarang; salin backup yang dipilih ke `%LOCALAPPDATA%\ResearchVault\vault.db`; hubungkan dongle yang aktif pada saat backup; buka aplikasi dan gunakan password yang berlaku saat backup dibuat. Jangan menimpa file ketika aplikasi masih berjalan. Pemulihan lintas PC belum didukung.

Password atau key store hilang berarti catatan dapat tidak dipulihkan. Hilangnya semua dongle aktif juga menghalangi login. Daftarkan USB cadangan selama sesi masih terbuka.

## Pemecahan masalah

- **`py`/Python 3.12 tidak ditemukan:** pasang Python 3.12 x64 beserta launcher. Jangan mengubah versi skrip sembarangan sebelum memeriksa dependency.
- **Compiler/SDK tidak ditemukan:** buka Visual Studio Installer, tambahkan workload C++ dan Windows 11 SDK, lalu ulangi `BUILD_HELLO.bat`.
- **USB tidak muncul:** gunakan flashdisk biasa yang memiliki serial. Drive jaringan, folder lokal, dan perangkat tanpa identitas stabil sengaja ditolak. Adapter yang melaporkan identitas USB nonstandar perlu pengujian/penyesuaian di Windows.
- **USB pernah diregistrasikan:** jangan hapus token dari dongle aktif. Gunakan USB lain untuk registrasi baru. Apabila proses registrasi terputus sebelum akun tercipta, setelah memastikan instalasi memang belum memiliki akun, hapus token yatim di USB lalu ulangi registrasi.
- **Hello dibatalkan/tidak tersedia:** vault tetap terkunci. Periksa pengaturan Windows dan adapter DLL. PIN dapat tersedia di dialog sistem; itu bukan bukti biometrik.
- **Tujuan sudah ada:** pilih nama output baru. Aplikasi tidak menimpa file yang ada meskipun dialog OS menawarkan overwrite.
- **Passphrase salah/data berubah:** tidak ada plaintext parsial yang disimpan. Gunakan passphrase yang tepat dan salinan ciphertext yang utuh.
- **Ekstensi file hasil dekripsi:** format baru memulihkan nama dan ekstensi otomatis saat memilih folder tujuan. Untuk format lama tanpa metadata, isi kolom Ekstensi file lama, misalnya `.pdf`.
- **PNG gagal diekstrak:** pilih gambar keluaran asli; resize, JPEG, filter, atau screenshot dapat merusak LSB.

## Pengujian

Jalankan `TEST.bat`, atau `.venv\Scripts\python.exe -m pytest tests -q` setelah memasang `requirements-dev.txt`.
Lihat `docs/HASIL_UJI.md` untuk hasil aktual dan `docs/UJI_WINDOWS.md` untuk uji penerimaan yang belum dilakukan.

Aplikasi adalah prototipe pendidikan. Caesar dan Vigenère merupakan lapisan pembelajaran, perlindungan modern teks berasal dari AES-GCM dan ChaCha20-Poly1305. Empat lapisan bukan klaim empat kali lebih aman. Flashdisk pasif dapat dikloning; ledger lokal dapat dibangun ulang oleh penguasa database. Aplikasi tidak melindungi dari malware/admin lokal yang menguasai sesi Windows atau memodifikasi executable.
