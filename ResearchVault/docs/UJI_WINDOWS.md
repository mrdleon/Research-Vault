# Uji penerimaan Windows — belum dijalankan

Isi tanggal, Windows build, Python, pywin32, compiler/SDK, merek sensor, jenis USB, dan hasil aktual. Jangan mengisi Lulus berdasarkan test double.

| Uji fisik | Hasil aktual |
|---|---|
| INSTALL.bat menyelesaikan install dependency dan kompilasi DLL x64 | Belum diuji |
| START.bat membuka jendela pada Windows 11 | Belum diuji |
| Registrasi USB dengan serial/PnP/volume yang stabil | Belum diuji |
| Windows Hello membuka dialog dengan parent window yang benar | Belum diuji |
| Login memakai sidik jari/wajah nyata | Belum diuji |
| Hello batal/gagal/perangkat tidak tersedia menolak akses | Belum diuji |
| PIN tidak dilabeli keberhasilan biometrik; bila dosen mewajibkan penolakan PIN, API ini belum memenuhi kebijakan tersebut | Batas desain |
| USB dipindah drive letter tetap dikenali | Belum diuji |
| Token disalin ke USB berbeda ditolak | Belum diuji |
| USB dicabut saat idle dan saat worker berjalan mengunci vault serta membuang hasil lama | Belum diuji |
| Windows+L mengunci vault; unlock Windows tidak otomatis membuka vault | Belum diuji |
| Idle lima menit tanpa aktivitas mengunci vault | Belum diuji |
| DPAPI menolak salinan key store dari akun Windows berbeda | Belum diuji |
| USB cadangan berfungsi setelah dongle lama dicabut statusnya | Belum diuji |
| File tepat 25 MiB dienkripsi tanpa UI membeku pada laptop target | Belum diuji |
| GUI pada DPI 100/125/150% dan layar 1024×720 | Belum diuji di Windows |
| Disk penuh/izin ditolak/target sudah ada tidak merusak sumber | Target sudah ada diuji otomatis; kondisi OS lain belum diuji |
| Ganti password dan restart membuka catatan lama dengan DPAPI nyata | Belum diuji |
| Restore backup pada komputer/akun sama | Diisolasi secara otomatis; DPAPI nyata belum diuji |
| BUILD_EXE.bat dan paket hasilnya bekerja di komputer tujuan | Belum diuji |

## Bukti yang disarankan untuk tugas

Rekam singkat login dengan sensor; screenshot dashboard sesudah login; contoh ciphertext; hash sumber/hasil dekripsi; tampilan BLOB catatan tanpa isi; PNG sebelum/sesudah; hasil file cocok/berbeda; penolakan login tanpa dongle. Jangan merekam password atau token USB.

## Tambahan penerimaan versi 2

| Skenario | Status |
|---|---|
| Migrasi database lama pada Windows dan login dengan dongle lama | Belum diuji pada Windows nyata |
| Registrasi akun kedua pada SID sama dengan USB lain | Belum diuji pada Windows nyata |
| Login bergantian, isolasi catatan/aset, USB salah dan Hello dibatalkan | Belum diuji pada Windows nyata |
| Enkripsi RVTXT2, ekspor, restart, impor, dekripsi (Caesar 1, 3, 25) | Lulus otomatis dengan test double; perlu uji Windows |
| Impor dan dekripsi TXT RVTXT1 produksi dari laptop pengguna | Fixture asli v1 lulus otomatis; perlu uji file pengguna |
| EXE dibangun ulang dan dijalankan dari folder dist lengkap | Belum diuji pada Windows nyata |
