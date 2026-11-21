# Hasil pengujian ResearchVault 2.1

Tanggal 17 November 2026. **131 tes lulus dalam 29,74 detik.** Output mentah ada pada pytest-output.txt.

Lingkungan: Linux, Python 3.12.14, PySide6 6.12.0, cryptography 50.0.0, Pillow 13.0.0; Qt offscreen. Hardware Windows digantikan TestPlatform khusus pengujian.

Perintah: `QT_QPA_PLATFORM=offscreen PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest ResearchVault/tests -q` dari direktori induk. Untuk Windows jalankan TEST.bat dari folder proyek.

Tambahan pengujian 2.1:
- Pemulihan nama, bytes dan SHA-256: PDF raster, DOCX minimal yang valid, PNG, CSV, teks Unicode, file tanpa ekstensi, file kosong.
- PDF/DOCX/PNG dihasilkan sebagai format dokumen/gambar, bukan sekadar file biner yang diganti ekstensi; PNG diverifikasi dengan Pillow dan arsip DOCX diperiksa dengan zipfile.
- File asli dihapus sebelum dekripsi dalam test: pemulihan tidak bergantung pada sumber asli yang masih ada.
- Dekripsi ke folder yang sudah memiliki nama sama tidak menimpa sumber maupun hasil sebelumnya.
- Penambahan ekstensi untuk path hasil tanpa ekstensi; penolakan ekstensi hasil baru yang tidak sesuai.
- Pembaca .rvault lama, ekstensi manual dan nama sumber yang masih menyertakan ekstensi.
- Salah password, tag rusak, file terpotong, path traversal metadata serta SHA-256 tidak cocok ditolak.
- GUI enkripsi → berganti mode → memilih folder → dekripsi; kolom tujuan dan password lama dibersihkan.
- Seluruh regresi akun, migrasi database, enkripsi teks empat tahap, file maksimum 25 MiB, catatan, stego, ledger, backup dan guard sesi tetap lulus.

Tampilan enkripsi/dekripsi file diperiksa pada 1024×720. Kontrol utama terbaca dan tidak terpotong. Windows Hello, DPAPI, WMI, USB fisik, DPI Windows, kompilasi C++ serta EXE belum diuji dalam lingkungan Linux ini.

Pasangan file gagal milik pengguna belum tersedia untuk pembandingan langsung. Laporan ini membuktikan perilaku terhadap fixture pengujian, bukan audit file pengguna tersebut.
