"""Indonesian Qt desktop interface; expensive operations run outside the GUI thread."""
import ctypes
import os
from pathlib import Path
import sys
from PySide6.QtCore import Qt, QObject, Signal, QRunnable, QThreadPool, QTimer, QEvent
from PySide6.QtGui import QFont, QPixmap
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QPlainTextEdit, QComboBox, QStackedWidget,
    QListWidget, QListWidgetItem, QFileDialog, QMessageBox, QInputDialog, QFrame,
    QProgressBar, QScrollArea, QSplitter, QSpinBox)
from .crypto import VaultError
from . import stego

STYLE = '''
QWidget {font-family: "Segoe UI"; font-size: 11pt; color:#2D3748; background:#F8F9FA;}
QMainWindow {background:#F8F9FA;}
QFrame#sidebar, QFrame#sidebar QLabel {background:#2A4365;color:white;}
QFrame#sidebar QPushButton {text-align:left;background:transparent;color:#E8F0F5;border:0;padding:13px;border-radius:7px;}
QFrame#sidebar QPushButton:checked {background:#0D5C75;color:white;}
QFrame#sidebar QPushButton:checked {background:#0D5C75;color:white;}
QPushButton:hover {background:#36597C;}
QLabel#title {font-size:23pt;font-weight:700;color:#0D5C75;}
QLabel#subtitle {color:#617286;font-size:10pt;}
QLabel#metric {font-size:28pt;font-weight:700;color:#0D5C75;background:white;}
QFrame#card {background:white;border:1px solid #D9E2E8;border-radius:10px;}
QFrame#card QLabel {background:white;}
QLineEdit,QPlainTextEdit,QListWidget,QComboBox,QSpinBox {background:white;border:1px solid #CAD6E0;border-radius:6px;padding:9px;selection-background-color:#0D5C75;}
QLineEdit:focus,QPlainTextEdit:focus {border:2px solid #0D5C75;}
QPushButton {background:#2F855A;color:white;border:0;border-radius:6px;padding:10px 16px;font-weight:600;}
QPushButton:checked {background:#0D5C75;color:white;}
QPushButton:hover {background:#256D49;}
QPushButton:disabled {background:#CED6DD;color:#62717E;}
QPushButton#secondary {background:#E7EFF3;color:#0D5C75;}
QPushButton#danger {background:#B42318;color:white;}
QProgressBar {border:0;background:#D9E2E8;max-height:4px;}
QProgressBar::chunk {background:#2F855A;}
QScrollArea {border:0;}
'''


class Signals(QObject):
    done = Signal(object)
    error = Signal(object)


class Job(QRunnable):
    def __init__(self, function):
        super().__init__()
        self.function = function
        self.signals = Signals()

    def run(self):
        try:
            self.signals.done.emit(self.function())
        except Exception as exc:
            self.signals.error.emit(exc)
        finally:
            self.function = None


def line(placeholder='', secret=False):
    widget = QLineEdit()
    widget.setPlaceholderText(placeholder)
    if secret:
        widget.setEchoMode(QLineEdit.Password)
    return widget


def button(text, callback, secondary=False, danger=False):
    widget = QPushButton(text)
    widget.setObjectName('danger' if danger else 'secondary' if secondary else '')
    widget.clicked.connect(callback)
    return widget


def label(text, name=None):
    widget = QLabel(text)
    widget.setWordWrap(True)
    if name:
        widget.setObjectName(name)
    return widget


def row(*widgets):
    layout = QHBoxLayout()
    layout.setSpacing(10)
    for widget in widgets:
        layout.addWidget(widget)
    return layout


def page(title, description):
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(26, 20, 26, 20)
    layout.setSpacing(14)
    layout.addWidget(label(title, 'title'))
    layout.addWidget(label(description, 'subtitle'))
    return widget, layout


class MainWindow(QMainWindow):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.setWindowTitle('ResearchVault — Dokumen penelitian Anda')
        self.resize(1280, 800)
        self.setMinimumSize(1024, 720)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(2)
        self.monitor_running = False
        self.monitor_job = None
        self.busy = False
        self.current_job = None
        self.copied = None
        self.note_id = None
        self.note_revision = None
        self.note_dirty = False
        self.note_data = []
        self.block_data = []
        self.status = label('Siap', 'subtitle')
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.root = QStackedWidget()
        self.setCentralWidget(self.root)
        self.build_access()
        self.build_shell()
        self.root.setCurrentIndex(0)
        self.statusBar().addWidget(self.status, 1)
        self.statusBar().addPermanentWidget(self.progress, 1)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll)
        self.timer.start(3000)
        QApplication.instance().installEventFilter(self)
        if sys.platform == 'win32':
            self.wts = ctypes.WinDLL('wtsapi32', use_last_error=True)
            self.wts.WTSRegisterSessionNotification.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            self.wts.WTSRegisterSessionNotification.restype = ctypes.c_int
            self.wts.WTSUnRegisterSessionNotification.argtypes = [ctypes.c_void_p]
            if not self.wts.WTSRegisterSessionNotification(int(self.winId()), 0):
                self.status.setText('Notifikasi lock Windows gagal didaftarkan; tutup aplikasi dan periksa instalasi.')

    def nativeEvent(self, event_type, message):
        if sys.platform == 'win32':
            from ctypes.wintypes import MSG
            msg = MSG.from_address(int(message))
            if msg.message == 0x02B1 and msg.wParam in (0x7, 0x6):
                self.lock_ui('Vault terkunci karena sesi Windows dikunci/dilepas.')
        return super().nativeEvent(event_type, message)

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.Wheel):
            self.engine.touch()
        return False

    def poll(self):
        if self.engine.user and not self.monitor_running:
            self.monitor_running = True
            generation = self.engine.generation
            job = Job(lambda: self.engine.guard(generation))
            self.monitor_job = job
            def done(_):
                self.monitor_running = False
                self.monitor_job = None
            def failed(_):
                done(None)
                if not self.engine.user:
                    self.lock_ui('Sesi terkunci. Periksa dongle dan masuk kembali.')
            job.signals.done.connect(done)
            job.signals.error.connect(failed)
            self.pool.start(job)
        elif self.root.currentIndex() == 1 and self.engine.user is None:
            self.lock_ui('Sesi terkunci. Masuk kembali.')

    def run(self, function, success=None, access=False, quiet=False):
        if self.busy:
            return
        self.busy = True
        generation = self.engine.generation
        self.access_box.setEnabled(False)
        self.pages.setEnabled(False)
        if not quiet:
            self.progress.show()
            self.status.setText('Memproses…')
        job = Job(function)
        self.current_job = job
        def finish():
            self.busy = False
            self.current_job = None
            self.access_box.setEnabled(True)
            self.pages.setEnabled(True)
            self.progress.hide()
        def done(result):
            finish()
            if not access and (generation != self.engine.generation or not self.engine.user):
                self.lock_ui('Sesi telah terkunci; hasil operasi tidak ditampilkan.')
                return
            if not quiet:
                self.status.setText('Operasi selesai.')
            if success:
                success(result)
        def error(exc):
            finish()
            if self.root.currentIndex() == 1 and not self.engine.user:
                self.lock_ui('Pemeriksaan sesi gagal. Hubungkan dongle lalu masuk kembali.')
            if isinstance(exc, VaultError):
                message = str(exc)
            elif isinstance(exc, OSError):
                message = 'File/perangkat tidak dapat diakses. Periksa lokasi, izin, ruang kosong, dan format folder tujuan.'
            else:
                message = 'Operasi gagal. Periksa input dan instalasi. Tidak ada hasil baru yang dapat digunakan.'
            self.status.setText(message)
            if not quiet:
                QMessageBox.warning(self, 'Operasi belum berhasil', message)
        job.signals.done.connect(done)
        job.signals.error.connect(error)
        self.pool.start(job)

    def build_access(self):
        self.access_box = QWidget()
        layout = QHBoxLayout(self.access_box)
        layout.setContentsMargins(64, 60, 64, 60)
        brand = QFrame()
        brand.setObjectName('sidebar')
        left = QVBoxLayout(brand)
        left.setContentsMargins(32, 40, 32, 40)
        left.addWidget(label('RV / RESEARCHVAULT'))
        left.addStretch()
        title = label('Riset berharga.\nSimpan dengan aman.')
        title.setFont(QFont('Segoe UI', 29, QFont.Bold))
        left.addWidget(title)
        left.addWidget(label('Satu ruang untuk dokumen, catatan, dan bukti integritas penelitian Anda.'))
        left.addStretch()
        left.addWidget(label('LOKAL  •  TERENKRIPSI  •  TERINTEGRASI'))
        layout.addWidget(brand, 1)
        right = QVBoxLayout()
        right.setContentsMargins(32, 20, 0, 20)
        self.access_registration = not self.engine.initialized()
        self.login_tab = button('Sudah punya akun · Login', lambda: self.set_access_mode(False))
        self.register_tab = button('Belum punya akun · Registrasi', lambda: self.set_access_mode(True))
        self.login_tab.setCheckable(True)
        self.register_tab.setCheckable(True)
        right.addLayout(row(self.login_tab, self.register_tab))
        self.access_title = label('', 'title')
        right.addWidget(self.access_title)
        right.addWidget(label('Akses memerlukan dongle USB, verifikasi Windows Hello, dan password akun. Windows Hello dapat menawarkan PIN; gunakan sensor untuk demonstrasi biometrik.'))
        self.username = line('Username (huruf kecil, angka, titik/garis)')
        self.display_name = line('Nama tampilan')
        self.login_password = line('Password minimal 12 karakter', True)
        self.login_confirm = line('Ulangi password', True)
        self.usb_combo = QComboBox()
        self.usb_combo.setPlaceholderText('Pilih flashdisk untuk dongle')
        self.scan_button = button('Cari USB', self.scan_usb, True)
        for widget in (self.username, self.display_name, self.login_password, self.login_confirm,
                       self.usb_combo, self.scan_button):
            right.addWidget(widget)
        self.access_action = button('', self.authenticate)
        right.addWidget(self.access_action)
        self.access_hint = label('', 'subtitle')
        right.addWidget(self.access_hint)
        right.addWidget(label('Tidak ada tombol lewati faktor akses. Pastikan Windows Hello telah diatur dan adapter Hello sudah dibangun.', 'subtitle'))
        right.addStretch()
        layout.addLayout(right, 1)
        self.root.addWidget(self.access_box)
        self.update_access()

    def set_access_mode(self, registration):
        if self.busy:
            return
        self.access_registration = bool(registration)
        for widget in (self.login_password, self.login_confirm, self.display_name):
            widget.clear()
        self.usb_combo.clear()
        self.update_access()

    def update_access(self):
        registration = self.access_registration
        self.login_tab.setChecked(not registration)
        self.register_tab.setChecked(registration)
        self.access_hint.setText(
            'Buat akun dengan username unik dan USB tanpa token. Setiap akun memakai dongle sendiri.'
            if registration else 'Masukkan username dan password, lalu hubungkan dongle akun tersebut.')
        self.access_title.setText('Registrasi akun baru' if registration else 'Selamat datang kembali')
        self.access_action.setText('Daftarkan akun dan dongle' if registration else 'Verifikasi dan masuk')
        for widget in (self.display_name, self.login_confirm, self.usb_combo, self.scan_button):
            widget.setVisible(registration)

    def scan_usb(self):
        self.run(self.engine.platform.devices, self.usb_results, access=True)

    def usb_results(self, devices):
        self.usb_combo.clear()
        for device in devices:
            self.usb_combo.addItem(device['label'], device['fingerprint'])
        if not devices:
            QMessageBox.information(self, 'USB', 'Belum ada USB dengan serial, PnP ID, dan volume ID yang dapat dibaca. Hubungkan flashdisk lalu coba lagi.')

    def authenticate(self):
        username, password, hwnd = self.username.text(), self.login_password.text(), int(self.winId())
        if self.access_registration:
            if password != self.login_confirm.text():
                return self.warn('Konfirmasi password tidak sama.')
            fingerprint, name = self.usb_combo.currentData(), self.display_name.text()
            if not fingerprint:
                return self.warn('Pilih USB melalui Cari USB terlebih dahulu.')
            def registered(_):
                self.login_password.clear()
                self.login_confirm.clear()
                self.set_access_mode(False)
                QMessageBox.information(self, 'Registrasi selesai', 'Akun dan dongle dibuat. Silakan login dengan semua faktor akses.')
            self.run(lambda: self.engine.register(username, name, password, fingerprint, hwnd), registered, access=True)
        else:
            def logged_in(name):
                self.login_password.clear()
                self.root.setCurrentIndex(1)
                self.profile_name.setText(name)
                self.welcome.setText(f'Ruang penelitian {name}')
                self.navigate(0)
            self.run(lambda: self.engine.login(username, password, hwnd), logged_in, access=True)

    def build_shell(self):
        shell = QWidget()
        layout = QHBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        side = QFrame()
        side.setObjectName('sidebar')
        side.setFixedWidth(224)
        nav = QVBoxLayout(side)
        nav.setContentsMargins(18, 24, 18, 20)
        nav.setSpacing(8)
        brand = label('RV /\nResearchVault')
        brand.setFont(QFont('Segoe UI', 20, QFont.Bold))
        nav.addWidget(brand)
        nav.addWidget(label('WORKSPACE PENELITIAN'))
        nav.addSpacing(22)
        self.nav_buttons = []
        for i, title in enumerate(('Ringkasan', 'Enkripsi teks', 'Enkripsi file', 'Catatan aman', 'Steganografi', 'Verifikasi aset', 'Keamanan & profil')):
            item = button(title, lambda checked=False, index=i: self.navigate(index))
            item.setCheckable(True)
            nav.addWidget(item)
            self.nav_buttons.append(item)
        nav.addStretch()
        nav.addWidget(label('Sesi otomatis terkunci\nsetelah 5 menit tidak aktif.'))
        nav.addWidget(button('Kunci vault', self.manual_lock))
        layout.addWidget(side)
        self.pages = QStackedWidget()
        layout.addWidget(self.pages, 1)
        for builder in (self.build_dashboard, self.build_text, self.build_files, self.build_notes,
                        self.build_stego, self.build_assets, self.build_security):
            widget = builder()
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(widget)
            self.pages.addWidget(scroll)
        self.root.addWidget(shell)

    def navigate(self, index):
        if self.busy:
            return
        if self.pages.currentIndex() == 3 and index != 3 and not self.discard_ok():
            return
        self.pages.setCurrentIndex(index)
        for i, item in enumerate(self.nav_buttons):
            item.setChecked(i == index)
        if index in (0, 6):
            self.run(self.engine.summary, self.show_summary)
        elif index == 3:
            self.refresh_notes()
        elif index == 5:
            self.asset_status.setText('Klik Validasi rantai untuk memeriksa catatan terbaru.')

    def build_dashboard(self):
        widget, layout = page('Ringkasan vault', 'Dokumen, pengetahuan, dan integritas riset dalam satu ruang kerja.')
        self.welcome = label('Ruang penelitian Anda')
        layout.addWidget(self.welcome)
        metrics = QHBoxLayout()
        self.metrics = []
        for name in ('Catatan aman', 'File dienkripsi', 'Aset tercatat'):
            card = QFrame()
            card.setObjectName('card')
            box = QVBoxLayout(card)
            box.setContentsMargins(20, 20, 20, 20)
            box.addWidget(label(name))
            value = label('—', 'metric')
            box.addWidget(value)
            self.metrics.append(value)
            metrics.addWidget(card)
        layout.addLayout(metrics)
        layout.addWidget(label('Mulai bekerja'))
        layout.addLayout(row(button('Amankan file', lambda: self.navigate(2)),
                             button('Tulis catatan', lambda: self.navigate(3)),
                             button('Periksa aset', lambda: self.navigate(5))))
        layout.addWidget(label('Aktivitas terbaru · metadata saja'))
        self.activity = QListWidget()
        layout.addWidget(self.activity, 1)
        layout.addWidget(label('USB dipantau selama sesi. Isi yang belum disimpan dibuang saat vault terkunci. Rantai aset belum dinyatakan valid sampai diperiksa.', 'subtitle'))
        return widget

    def show_summary(self, data):
        for value, count in zip(self.metrics, data['counts']):
            value.setText(str(count))
        self.activity.clear()
        for event in data['logs']:
            self.activity.addItem(f"{event['timestamp'][:19].replace('T',' ')} UTC  ·  {event['event_type']}  ·  {event['outcome']}")
        self.dongle_list.clear()
        for item in data['dongles']:
            entry = QListWidgetItem(f"{item['id'][:8]}  ·  {item['status']}  ·  perangkat {item['fingerprint'][:10]}")
            entry.setData(Qt.UserRole, item['id'])
            self.dongle_list.addItem(entry)

    def build_text(self):
        widget, layout = page('Enkripsi teks', 'Caesar → Vigenère → AES-256-GCM → ChaCha20-Poly1305. Dekripsi membalik urutan tersebut; Unicode tetap utuh.')
        self.text_result_encrypted = False
        self.text_mode = QComboBox()
        self.text_mode.addItems(['Enkripsi pesan', 'Dekripsi RVTXT2 / RVTXT1 lama'])
        layout.addWidget(self.text_mode)
        editors = QSplitter(Qt.Horizontal)
        self.text_input = QPlainTextEdit()
        self.text_input.setPlaceholderText('Tulis pesan atau tempel envelope di sini…')
        self.text_output = QPlainTextEdit()
        self.text_output.setReadOnly(True)
        self.text_output.setPlaceholderText('Hasil terverifikasi ditampilkan di sini')
        editors.addWidget(self.text_input)
        editors.addWidget(self.text_output)
        layout.addWidget(editors, 1)
        self.caesar_shift = QSpinBox()
        self.caesar_shift.setRange(1, 25)
        self.caesar_shift.setValue(3)
        self.caesar_shift.setPrefix('Caesar: ')
        self.caesar_shift.setAccessibleName('Pergeseran Caesar 1 sampai 25')
        self.caesar_shift.setToolTip('Simpan angka ini untuk dekripsi RVTXT2. Diabaikan untuk RVTXT1 lama.')
        self.vigenere = line('Kunci Vigenère: A–Z', True)
        self.text_password = line('Passphrase AES + ChaCha20 (min. 12 karakter)', True)
        self.text_confirm = line('Konfirmasi passphrase saat enkripsi', True)
        layout.addLayout(row(self.caesar_shift, self.vigenere))
        layout.addLayout(row(self.text_password, self.text_confirm))
        layout.addLayout(row(button('Proses teks', self.process_text),
                             button('Salin hasil', self.copy_result, True),
                             button('Bersihkan', self.clear_text, True)))
        self.export_text_button = button('Ekspor hasil enkripsi', self.export_text_result, True)
        self.export_text_button.setEnabled(False)
        self.import_text_button = button('Impor teks terenkripsi', self.import_text_file, True)
        layout.addLayout(row(self.export_text_button, self.import_text_button))
        self.text_mode.currentIndexChanged.connect(self.reset_text_result)
        layout.addWidget(label('Ekspor RVTXT2 ke .txt tanpa kunci. Dekripsi: masukkan angka Caesar, kunci Vigenère, dan passphrase. RVTXT1 lama tetap didukung tanpa Caesar. Satu passphrase diturunkan menjadi dua kunci modern yang berbeda.', 'subtitle'))
        return widget

    def process_text(self):
        decrypt = self.text_mode.currentIndex() == 1
        value, key, password = self.text_input.toPlainText(), self.vigenere.text(), self.text_password.text()
        shift = self.caesar_shift.value()
        self.reset_text_result()
        if not decrypt and password != self.text_confirm.text():
            return self.warn('Konfirmasi passphrase tidak sama.')
        def completed(result):
            self.text_output.setPlainText(result)
            self.text_result_encrypted = not decrypt
            self.export_text_button.setEnabled(not decrypt)
        self.run(lambda: self.engine.text(value, key, password, decrypt, shift), completed)

    def reset_text_result(self, *_):
        self.text_result_encrypted = False
        self.text_output.clear()
        self.export_text_button.setEnabled(False)

    def export_text_result(self):
        if not self.text_result_encrypted or not self.text_output.toPlainText():
            return self.warn('Enkripsi pesan terlebih dahulu untuk mengekspor hasilnya.')
        value = self.text_output.toPlainText()
        path, _ = QFileDialog.getSaveFileName(self, 'Ekspor hasil enkripsi', 'pesan_terenkripsi.txt', 'Teks terenkripsi (*.txt)')
        if not path:
            return
        if not Path(path).suffix:
            path += '.txt'
        self.run(lambda: self.engine.export_text(value, path),
                 lambda output: self.status.setText('Teks terenkripsi tersimpan: ' + output))

    def import_text_file(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Impor teks terenkripsi', '', 'Teks terenkripsi (*.txt);;Semua file (*)')
        if not path:
            return
        if self.text_input.toPlainText().strip():
            answer = QMessageBox.question(self, 'Ganti input teks',
                'Ganti input saat ini dengan isi file terenkripsi?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
        self.reset_text_result()
        def imported(value):
            self.text_mode.setCurrentIndex(1)
            self.text_input.setPlainText(value)
            for secret in (self.vigenere, self.text_password, self.text_confirm):
                secret.clear()
            self.caesar_shift.setValue(3)
            self.vigenere.setFocus()
            self.status.setText('File dimuat. Masukkan angka Caesar, kunci Vigenère, dan passphrase lalu Proses teks. Untuk RVTXT1, Caesar diabaikan. Integritas diperiksa saat dekripsi.')
        self.run(lambda: self.engine.import_text(path), imported)

    def copy_result(self):
        self.copied = self.text_output.toPlainText()
        QApplication.clipboard().setText(self.copied)

    def clear_text(self):
        self.caesar_shift.setValue(3)
        self.reset_text_result()
        for widget in (self.text_input, self.text_output, self.vigenere, self.text_password, self.text_confirm):
            widget.clear()

    def build_files(self):
        widget, layout = page('Enkripsi file', 'ChaCha20-Poly1305 menjaga kerahasiaan dan memeriksa integritas file. Maksimal 25 MiB.')
        self.file_mode = QComboBox()
        self.file_mode.addItems(['Enkripsi menjadi .rvault', 'Dekripsi menjadi file asli'])
        self.file_source = line('Lokasi file sumber')
        self.file_target = line('Lokasi file hasil baru')
        self.file_password = line('Passphrase minimal 12 karakter', True)
        self.file_confirm = line('Konfirmasi passphrase saat enkripsi', True)
        layout.addWidget(self.file_mode)
        layout.addWidget(label('1 / Pilih sumber'))
        layout.addLayout(row(self.file_source, button('Pilih file', lambda: self.choose(self.file_source), True)))
        layout.addWidget(label('2 / Tentukan hasil baru'))
        self.file_target_button = button('Simpan sebagai', self.choose_file_target, True)
        layout.addLayout(row(self.file_target, self.file_target_button))
        self.legacy_extension = line('Ekstensi file lama jika diperlukan, misalnya .pdf atau .docx')
        self.legacy_extension.hide()
        layout.addWidget(self.legacy_extension)
        layout.addWidget(label('3 / Masukkan passphrase'))
        layout.addLayout(row(self.file_password, self.file_confirm))
        layout.addWidget(button('Proses file', self.process_file))
        self.file_result = label('Belum ada hasil.')
        self.file_mode.currentIndexChanged.connect(self.file_mode_changed)
        self.file_source.textChanged.connect(self.file_source_changed)
        layout.addWidget(self.file_result)
        layout.addStretch()
        layout.addWidget(label('Enkripsi baru menyimpan nama dan ekstensi asli secara terenkripsi. Saat dekripsi pilih folder tujuan; nama dipulihkan otomatis tanpa menimpa file lama. Untuk .rvault versi lama, isi ekstensi asli jika diminta.', 'subtitle'))
        return widget

    def choose(self, edit, filter='Semua file (*)'):
        path, _ = QFileDialog.getOpenFileName(self, 'Pilih file', '', filter)
        if path:
            edit.setText(path)
        return path

    def file_source_changed(self, *_):
        self.file_target.clear()
        self.file_result.setText('Belum ada hasil baru.')

    def file_mode_changed(self, *_):
        decrypt = self.file_mode.currentIndex() == 1
        self.file_target.clear()
        self.file_password.clear()
        self.file_confirm.clear()
        self.legacy_extension.clear()
        self.legacy_extension.setVisible(decrypt)
        self.file_confirm.setVisible(not decrypt)
        self.file_target_button.setText('Pilih folder hasil' if decrypt else 'Simpan sebagai')
        self.file_target.setPlaceholderText('Folder untuk file asli hasil dekripsi' if decrypt else 'Lokasi file hasil baru .rvault')
        self.file_result.setText('Belum ada hasil baru.')

    def choose_file_target(self):
        if self.file_mode.currentIndex() == 1:
            path = QFileDialog.getExistingDirectory(self, 'Pilih folder hasil dekripsi')
            if path:
                self.file_target.setText(path)
        else:
            name = Path(self.file_source.text()).name or 'dokumen'
            path = self.save_dialog(self.file_target, name + '.rvault', 'ResearchVault (*.rvault)')
            if path and not path.lower().endswith('.rvault'):
                self.file_target.setText(path + '.rvault')

    def save_dialog(self, edit, default, filter):
        path, _ = QFileDialog.getSaveFileName(self, 'Simpan sebagai file baru', default, filter)
        if path:
            edit.setText(path)
        return path

    def process_file(self):
        source, target, password = self.file_source.text(), self.file_target.text(), self.file_password.text()
        decrypt = self.file_mode.currentIndex() == 1
        self.file_result.setText('Belum ada hasil baru.')
        if not source or not target:
            return self.warn('Pilih file sumber dan lokasi hasil.')
        if not decrypt and password != self.file_confirm.text():
            return self.warn('Konfirmasi passphrase tidak sama.')
        if not decrypt and not target.lower().endswith('.rvault'):
            target += '.rvault'
            self.file_target.setText(target)
        extension = self.legacy_extension.text()
        self.run(lambda: self.engine.file(source, target, password, decrypt, extension),
                 lambda path: self.file_result.setText('Berhasil disimpan: ' + path))

    def build_notes(self):
        widget, layout = page('Catatan penelitian aman', 'Judul dan isi dienkripsi di database. Isi yang belum disimpan akan dibuang saat vault terkunci.')
        split = QSplitter(Qt.Horizontal)
        left, right = QWidget(), QWidget()
        a, b = QVBoxLayout(left), QVBoxLayout(right)
        self.note_search = line('Cari judul dalam sesi ini…')
        self.note_search.textChanged.connect(self.filter_notes)
        self.note_list = QListWidget()
        self.note_list.itemClicked.connect(self.select_note)
        a.addWidget(self.note_search)
        a.addWidget(self.note_list)
        a.addWidget(button('Catatan baru', self.new_note, True))
        self.note_title = line('Judul catatan')
        self.note_body = QPlainTextEdit()
        self.note_body.setPlaceholderText('Metodologi, hasil eksperimen, atau ide penelitian…')
        self.note_title.textChanged.connect(self.mark_dirty)
        self.note_body.textChanged.connect(self.mark_dirty)
        b.addWidget(self.note_title)
        b.addWidget(self.note_body)
        b.addLayout(row(button('Simpan catatan', self.save_note), button('Hapus', self.remove_note, danger=True)))
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([270, 620])
        layout.addWidget(split, 1)
        return widget

    def mark_dirty(self):
        self.note_dirty = True

    def discard_ok(self):
        if not self.note_dirty:
            return True
        result = QMessageBox.question(self, 'Perubahan belum disimpan', 'Buang perubahan catatan yang belum disimpan?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if result == QMessageBox.Yes:
            self.note_dirty = False
            self.note_title.clear()
            self.note_body.clear()
            self.note_dirty = False
            return True
        return False

    def refresh_notes(self):
        self.run(self.engine.notes, self.show_notes)

    def show_notes(self, notes):
        self.note_data = notes
        self.filter_notes()

    def filter_notes(self):
        self.note_list.clear()
        for note in self.note_data:
            if self.note_search.text().casefold() in note['title'].casefold():
                item = QListWidgetItem(note['title'])
                item.setData(Qt.UserRole, note['id'])
                self.note_list.addItem(item)

    def select_note(self, item):
        selected_id = item.data(Qt.UserRole)
        if not self.discard_ok():
            return
        note = next(x for x in self.note_data if x['id'] == selected_id)
        self.note_id, self.note_revision = note['id'], note['revision']
        self.note_title.setText(note['title'])
        self.note_body.setPlainText(note['body'])
        self.note_dirty = False

    def new_note(self):
        if not self.discard_ok():
            return
        self.note_id = self.note_revision = None
        self.note_title.clear()
        self.note_body.clear()
        self.note_dirty = False

    def save_note(self):
        title, body, note_id, revision = self.note_title.text(), self.note_body.toPlainText(), self.note_id, self.note_revision
        def saved(_):
            self.note_dirty = False
            self.new_note()
            self.refresh_notes()
        self.run(lambda: self.engine.save_note(title, body, note_id, revision), saved)

    def remove_note(self):
        if not self.note_id:
            return self.warn('Pilih catatan yang sudah disimpan.')
        if QMessageBox.question(self, 'Hapus catatan', 'Hapus catatan terpilih?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        note_id = self.note_id
        def removed(_):
            self.note_dirty = False
            self.new_note()
            self.refresh_notes()
        self.run(lambda: self.engine.delete_note(note_id), removed)

    def build_stego(self):
        widget, layout = page('Steganografi gambar', 'Sembunyikan pesan terenkripsi pada bit terendah kanal RGB. Kanal alpha dipertahankan.')
        self.stego_source = line('Pilih gambar PNG RGB/RGBA')
        layout.addLayout(row(self.stego_source, button('Pilih PNG', self.choose_png, True)))
        self.stego_info = label('Maksimal 20 megapiksel. Simpan dan kirim hasil sebagai PNG tanpa resize.')
        layout.addWidget(self.stego_info)
        self.stego_preview = QLabel('Pratinjau gambar')
        self.stego_preview.setAlignment(Qt.AlignCenter)
        self.stego_preview.setFixedHeight(140)
        layout.addWidget(self.stego_preview)
        self.stego_message = QPlainTextEdit()
        self.stego_message.setPlaceholderText('Pesan untuk disisipkan; hasil ekstraksi juga muncul di sini')
        layout.addWidget(self.stego_message, 1)
        self.stego_password = line('Passphrase minimal 12 karakter', True)
        self.stego_confirm = line('Konfirmasi passphrase untuk penyisipan', True)
        layout.addLayout(row(self.stego_password, self.stego_confirm))
        layout.addLayout(row(button('Sisipkan & simpan PNG', self.embed_image),
                             button('Ekstrak pesan', self.extract_image, True)))
        return widget

    def choose_png(self):
        path = self.choose(self.stego_source, 'PNG (*.png)')
        if not path:
            return
        self.stego_preview.clear()
        def info(result):
            width, height, cap = result
            self.stego_info.setText(f'{width} × {height} piksel  ·  kapasitas envelope {cap:,} byte (termasuk overhead enkripsi)')
            pixmap = QPixmap(path)
            self.stego_preview.setPixmap(pixmap.scaled(480, 140, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.run(lambda: stego.capacity(path), info)

    def embed_image(self):
        source, password, message = self.stego_source.text(), self.stego_password.text(), self.stego_message.toPlainText()
        if password != self.stego_confirm.text():
            return self.warn('Konfirmasi passphrase tidak sama.')
        path, _ = QFileDialog.getSaveFileName(self, 'Simpan PNG baru', 'pesan-stego.png', 'PNG (*.png)')
        if path:
            self.run(lambda: self.engine.image(source, password, message, path), lambda output: self.status.setText('PNG tersimpan: ' + output))

    def extract_image(self):
        source, password = self.stego_source.text(), self.stego_password.text()
        self.stego_message.clear()
        self.run(lambda: self.engine.image(source, password), self.stego_message.setPlainText)

    def build_assets(self):
        widget, layout = page('Verifikasi aset', 'Ledger lokal berbasis SHA-256. Pemeriksaan rantai dan kecocokan file adalah dua hasil berbeda.')
        self.asset_source = line('File yang akan didaftarkan')
        self.asset_name = line('Alias aset — metadata ini tidak dienkripsi')
        layout.addLayout(row(self.asset_source, button('Pilih file', lambda: self.choose(self.asset_source), True)))
        layout.addLayout(row(self.asset_name, button('Daftarkan aset', self.add_asset)))
        self.asset_list = QListWidget()
        self.asset_list.itemClicked.connect(self.asset_detail)
        layout.addWidget(self.asset_list, 1)
        self.asset_details = QPlainTextEdit()
        self.asset_details.setReadOnly(True)
        self.asset_details.setMaximumHeight(115)
        layout.addWidget(self.asset_details)
        layout.addLayout(row(button('Validasi rantai', self.validate_chain), button('Verifikasi file pembanding', self.compare_asset, True)))
        self.asset_status = label('Rantai belum diperiksa.')
        layout.addWidget(self.asset_status)
        layout.addWidget(label('Rantai lokal mendeteksi perubahan parsial. Pihak yang menguasai seluruh database dapat membangun ulang rantai; ini bukan blockchain terdistribusi.', 'subtitle'))
        return widget

    def add_asset(self):
        source, name = self.asset_source.text(), self.asset_name.text()
        self.run(lambda: self.engine.register_asset(source, name), lambda _: self.validate_chain())

    def validate_chain(self):
        self.asset_status.setText('Memeriksa rantai…')
        self.asset_list.clear()
        self.asset_details.clear()
        def show(blocks):
            self.block_data = blocks
            for item in blocks:
                entry = QListWidgetItem(f"#{item['index']:03d}  ·  {item['name'] or 'GENESIS'}  ·  {item['current_hash'][:20]}…")
                entry.setData(Qt.UserRole, item['index'])
                self.asset_list.addItem(entry)
            self.asset_status.setText(f'Rantai konsisten · {len(blocks)} blok. Kecocokan file eksternal belum diperiksa.')
        self.run(self.engine.blocks, show)

    def asset_detail(self, item):
        block = self.block_data[item.data(Qt.UserRole)]
        self.asset_details.setPlainText(f"Hash blok: {block['current_hash']}\nPrevious: {block['previous_hash']}\nHash file: {block['file_hash'] or '—'}\nWaktu: {block['timestamp']}")

    def compare_asset(self):
        item = self.asset_list.currentItem()
        if not item or item.data(Qt.UserRole) == 0:
            return self.warn('Validasi rantai lalu pilih blok aset (bukan genesis).')
        index = item.data(Qt.UserRole)
        path, _ = QFileDialog.getOpenFileName(self, 'Pilih file pembanding')
        if path:
            self.asset_status.setText('Memeriksa file…')
            self.run(lambda: self.engine.verify_asset(index, path), lambda match: self.asset_status.setText('FILE COCOK dengan hash tercatat.' if match else 'FILE BERBEDA dari hash tercatat.'))

    def build_security(self):
        widget, layout = page('Keamanan & profil', 'Kelola identitas, dongle cadangan, dan pemulihan vault pada akun Windows yang sama.')
        self.profile_name = line('Nama tampilan')
        layout.addLayout(row(self.profile_name, button('Simpan nama', self.save_profile)))
        self.dongle_list = QListWidget()
        self.dongle_list.setMaximumHeight(130)
        layout.addWidget(label('Dongle terdaftar'))
        layout.addWidget(self.dongle_list)
        layout.addLayout(row(button('Daftarkan dongle cadangan', self.add_dongle),
                             button('Cabut dongle terpilih', self.revoke_dongle, danger=True)))
        layout.addLayout(row(button('Ganti password', self.change_password, True), button('Backup vault', self.backup, True)))
        layout.addWidget(label('Idle timeout: 5 menit. Windows lock, logout, atau pencabutan USB mengunci vault. Backup berisi ciphertext dan key store terlindungi; pulihkan hanya pada komputer dan akun Windows yang sama.'))
        layout.addWidget(label('Windows Hello dapat menerima PIN. Aplikasi tidak mengklaim PIN sebagai biometrik. Uji sidik jari/wajah nyata sebelum demonstrasi tugas.', 'subtitle'))
        layout.addWidget(label('Token flashdisk biasa dapat disalin dan bukan hardware security key. Password hilang atau key store rusak tidak dapat direset untuk membuka catatan lama.', 'subtitle'))
        layout.addStretch()
        return widget

    def ask_password(self):
        password, okay = QInputDialog.getText(self, 'Autentikasi ulang', 'Password akun saat ini:', QLineEdit.Password)
        return password if okay else None

    def save_profile(self):
        name = self.profile_name.text()
        self.run(lambda: self.engine.profile(name), lambda _: self.welcome.setText(f'Ruang penelitian {name}'))

    def change_password(self):
        old = self.ask_password()
        if old is None:
            return
        new, okay = QInputDialog.getText(self, 'Password baru', 'Minimal 12 karakter:', QLineEdit.Password)
        if not okay:
            return
        confirm, okay = QInputDialog.getText(self, 'Konfirmasi', 'Ulangi password baru:', QLineEdit.Password)
        if not okay:
            return
        if new != confirm:
            return self.warn('Konfirmasi tidak sama.')
        hwnd = int(self.winId())
        self.run(lambda: self.engine.change_password(old, new, hwnd), lambda _: self.status.setText('Password berhasil diubah. Catatan tetap dapat dibuka.'))

    def add_dongle(self):
        def select(devices):
            if not devices:
                return self.warn('USB yang memenuhi syarat belum ditemukan.')
            choice, okay = QInputDialog.getItem(self, 'Dongle cadangan', 'Pilih USB baru (token yang sudah ada tidak ditimpa):', [x['label'] for x in devices], 0, False)
            if not okay:
                return
            selected = next(x for x in devices if x['label'] == choice)
            password = self.ask_password()
            if password is None:
                return
            hwnd = int(self.winId())
            self.run(lambda: self.engine.add_dongle(selected['fingerprint'], password, hwnd), lambda _: self.navigate(6))
        self.run(self.engine.platform.devices, select)

    def revoke_dongle(self):
        item = self.dongle_list.currentItem()
        if not item:
            return self.warn('Pilih dongle terlebih dahulu.')
        password = self.ask_password()
        if password is None:
            return
        token_id, hwnd = item.data(Qt.UserRole), int(self.winId())
        self.run(lambda: self.engine.revoke_dongle(token_id, password, hwnd), lambda _: self.navigate(6))

    def backup(self):
        password = self.ask_password()
        if password is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Backup vault', 'ResearchVault-backup.db', 'Database (*.db)')
        if path:
            hwnd = int(self.winId())
            self.run(lambda: self.engine.backup(path, password, hwnd), lambda output: self.status.setText('Backup tersimpan: ' + output))

    def warn(self, message):
        QMessageBox.warning(self, 'Periksa input', message)

    def manual_lock(self):
        if self.discard_ok():
            self.lock_ui('Vault terkunci. Semua isi tampilan sudah dibersihkan.')

    def lock_ui(self, message):
        self.engine.lock()
        self.clear_text()
        for widget in (self.note_title, self.note_body, self.note_search, self.stego_message,
                       self.stego_password, self.stego_confirm, self.file_password, self.file_confirm,
                       self.login_password, self.login_confirm, self.asset_details, self.asset_source,
                       self.asset_name, self.file_source, self.file_target, self.legacy_extension, self.stego_source, self.profile_name):
            widget.clear()
        self.note_list.clear()
        self.asset_list.clear()
        self.activity.clear()
        self.dongle_list.clear()
        self.note_data = []
        self.block_data = []
        self.note_id = self.note_revision = None
        self.note_dirty = False
        self.stego_preview.clear()
        self.file_result.setText('Belum ada hasil.')
        self.stego_info.setText('Pilih PNG RGB/RGBA.')
        self.asset_status.setText('Rantai belum diperiksa.')
        if self.copied is not None and QApplication.clipboard().text() == self.copied:
            QApplication.clipboard().clear()
        self.copied = None
        self.root.setCurrentIndex(0)
        self.status.setText(message)

    def closeEvent(self, event):
        if self.busy:
            QMessageBox.information(self, 'Operasi berlangsung', 'Tunggu operasi atau tutup dialog Windows Hello, lalu tutup aplikasi kembali.')
            event.ignore()
            return
        if not self.discard_ok():
            event.ignore()
            return
        self.lock_ui('Ditutup')
        if sys.platform == 'win32':
            self.wts.WTSUnRegisterSessionNotification(int(self.winId()))
        event.accept()
