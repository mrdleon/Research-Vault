# Panduan penggunaan dan demonstrasi

Gunakan data dummy dari `examples/`. Jangan menggunakan data riset sungguhan sebelum uji penerimaan Windows selesai.

## 1. Registrasi dan login

Buka `START.bat`. Pada instalasi baru, isi username, nama, password, konfirmasi, lalu pilih USB melalui Cari USB. Verifikasi dialog Windows Hello. Setelah registrasi selesai, login normal. Tunjukkan bahwa tanpa USB, dengan password salah, atau saat Hello dibatalkan, dashboard tidak terbuka. Aplikasi tidak menyimpan sidik jari/wajah; verifikasi dikelola Windows.

## 2. Super encryption teks

Masukkan `Attack at dawn! Penelitian 🌱`, pergeseran Caesar `3`, kunci Vigenère `LEMON`, dan passphrase minimal 12 karakter beserta konfirmasi. Klik Proses teks. Ekspor hasil `RVTXT2:...` ke TXT, bersihkan formulir, impor TXT itu, lalu masukkan kembali ketiga input rahasia. Klik Proses teks untuk mengembalikan pesan. Ubah Caesar, Vigenère, atau passphrase secara bergantian untuk menunjukkan penolakan. Detail algoritma dan urutannya ada pada `crypto.py` dan `docs/UPGRADE_V2.md`.

## 3. Enkripsi file

Pilih `examples/dataset_dummy.csv`. Tentukan output baru seperti `dataset.rvault`, isi passphrase dan konfirmasi. Pilih mode Dekripsi, pilih `.rvault`, lalu output baru `dataset-hasil.csv` dengan passphrase sama. Bandingkan SHA-256 di PowerShell:

```powershell
Get-FileHash .\examples\dataset_dummy.csv -Algorithm SHA256
Get-FileHash .\dataset-hasil.csv -Algorithm SHA256
```

File memakai ChaCha20-Poly1305 satu tahap. Teks versi 2 memakai empat tahap termasuk AES-GCM dan ChaCha20-Poly1305. Dengan demikian, keduanya memiliki pipeline berbeda tetapi berbagi salah satu algoritma modern; jangan mengklaim algoritma modernnya sepenuhnya berbeda. Mulai versi 2.1, nama dan ekstensi disimpan dalam payload terenkripsi. Dekripsi dengan memilih folder hasil; untuk file lama tanpa metadata, masukkan ekstensi aslinya.

## 4. Catatan terenkripsi

Buat catatan berjudul `HASIL EKSPERIMEN RAHASIA` dan isi dummy. Simpan, pilih kembali, ubah isi, lalu simpan. Logout dan login kembali untuk menunjukkan persistensi. Pencarian judul bekerja hanya pada data yang didekripsi dalam sesi. Dengan SQLite viewer, kolom `ciphertext` berupa BLOB; judul/isi tidak masuk query, indeks pencarian, atau audit.

## 5. Steganografi

Pilih `examples/cover_penelitian.png`, isi pesan dan passphrase beserta konfirmasi, klik Sisipkan & simpan PNG, dan beri nama baru. Pilih PNG hasil, masukkan passphrase yang sama, kemudian Ekstrak pesan. Pesan terenkripsi berada pada bit terendah kanal RGB; perbedaan tampilan biasanya sangat kecil. Jangan resize, screenshot, atau ubah ke JPEG.

## 6. Ledger aset

Daftarkan `dataset_dummy.csv` dengan alias `Dataset percobaan 1`. Klik Validasi rantai, pilih blok selain genesis, lalu Verifikasi file pembanding. Pilih file yang sama: harus cocok. Buat salinan file, ubah satu nilai, dan verifikasi salinan: harus berbeda. Validasi rantai tetap bisa konsisten walaupun file eksternal berubah. Rantai adalah pencatatan hash lokal, bukan penyimpanan dokumen terenkripsi dan bukan konsensus terdistribusi.

## 7. Keamanan sesi dan backup

Daftarkan USB cadangan sebelum mencabut dongle lama. Ganti password menggunakan password lama dan Hello, kemudian buktikan catatan lama tetap terbaca setelah restart. Buat backup dari halaman keamanan. Coba cabut USB aktif, tunggu pemeriksaan berkala (sekitar 3 detik ditambah waktu pemindaian WMI): tampilan harus dikosongkan dan sesi terkunci. Coba Windows+L dan tunggu idle 5 menit secara terpisah. Isi editor yang belum disimpan akan dibuang ketika lock.

## Alur presentasi singkat

1. Jelaskan masalah keamanan data penelitian dan batas prototipe.
2. Tunjukkan tiga faktor akses dan login dengan sensor nyata.
3. Bandingkan super encryption teks dan algoritma file.
4. Tunjukkan CRUD catatan dan database ciphertext.
5. Sisip/ekstrak pesan PNG.
6. Periksa file cocok/berubah dan rantai lokal.
7. Cabut dongle untuk mengunci aplikasi, lalu jelaskan backup dan keterbatasan.
