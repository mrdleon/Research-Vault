import hashlib
from pathlib import Path
import time
import pytest
from conftest import PASSWORD
from researchvault.crypto import VaultError, b64, seal, unb64
from researchvault.text_io import MAX_TEXT_EXPORT


def test_export_import_after_login(engine,tmp_path):
    message = 'Catatan penelitian: αβ 🌱\nJumlah sampel: 10'
    value = engine.text(message,'LEMON',PASSWORD)
    path = tmp_path/'hasil.txt'
    engine.export_text(value,path)
    assert path.read_text() == value
    assert PASSWORD.encode() not in path.read_bytes()
    engine.lock()
    engine.login('marvel',PASSWORD,1)
    imported = engine.import_text(path)
    assert engine.text(imported,'LEMON',PASSWORD,True) == message


@pytest.mark.parametrize('content', [b'plain text', b'RVTXT1:not-base64', b'\xff\xfe', b'RVTXT1:AAAA'])
def test_invalid_import(engine,tmp_path,content):
    path=tmp_path/'bad.txt';path.write_bytes(content)
    with pytest.raises(VaultError): engine.import_text(path)


def test_wrong_domain(engine,tmp_path):
    path=tmp_path/'file.txt'
    path.write_text('RVTXT1:'+b64(seal(b'test',PASSWORD,'file')))
    with pytest.raises(VaultError): engine.import_text(path)


def test_import_bom_and_final_newline(engine,tmp_path):
    value=engine.text('test','KEY',PASSWORD)
    path=tmp_path/'bom.txt';path.write_bytes(b'\xef\xbb\xbf'+value.encode()+b'\r\n')
    assert engine.import_text(path)==value


def test_export_no_overwrite(engine,tmp_path):
    path=tmp_path/'existing.txt';path.write_text('original')
    with pytest.raises(VaultError): engine.export_text(engine.text('test','KEY',PASSWORD),path)
    assert path.read_text()=='original'


def test_plaintext_export_rejected(engine,tmp_path):
    path=tmp_path/'bad.txt'
    with pytest.raises(VaultError): engine.export_text('secret plaintext',path)
    assert not path.exists()


def test_import_size_limit(engine,tmp_path):
    path=tmp_path/'large.txt';path.write_bytes(b'A'*(MAX_TEXT_EXPORT+4))
    with pytest.raises(VaultError): engine.import_text(path)


def test_import_tampered_ciphertext_not_authenticated_until_decrypt(engine,tmp_path):
    value=engine.text('message','KEY',PASSWORD)
    raw=bytearray(unb64(value[7:]));raw[-1]^=1
    path=tmp_path/'tampered.txt';path.write_text(value[:7]+b64(raw))
    imported=engine.import_text(path)
    with pytest.raises(VaultError): engine.text(imported,'KEY',PASSWORD,True)


def test_import_wrong_keys(engine,tmp_path):
    path=tmp_path/'encrypted.txt'
    engine.export_text(engine.text('message','KEY',PASSWORD),path)
    value=engine.import_text(path)
    with pytest.raises(VaultError): engine.text(value,'OTHER',PASSWORD,True)
    with pytest.raises(VaultError): engine.text(value,'KEY',PASSWORD+'wrong',True)


def test_transport_requires_session(engine,tmp_path):
    value=engine.text('message','KEY',PASSWORD)
    path=tmp_path/'encrypted.txt';engine.export_text(value,path)
    engine.lock()
    with pytest.raises(VaultError): engine.import_text(path)
    with pytest.raises(VaultError): engine.export_text(value,tmp_path/'another.txt')


def test_ui_export_import_decrypt(engine,tmp_path,monkeypatch):
    from PySide6.QtWidgets import QApplication,QFileDialog,QMessageBox
    from researchvault.ui import MainWindow,STYLE
    app=QApplication.instance() or QApplication([])
    app.setStyleSheet(STYLE)
    w=MainWindow(engine);w.timer.stop();w.root.setCurrentIndex(1);w.pages.setCurrentIndex(1)
    failures=[]
    monkeypatch.setattr(QMessageBox,'warning',lambda *args: failures.append(args[-1]))
    def wait():
        deadline=time.monotonic()+15
        while w.busy and time.monotonic()<deadline:
            app.processEvents();time.sleep(.01)
        app.processEvents()
        assert not w.busy
        assert not failures
    assert not w.export_text_button.isEnabled()
    w.text_input.setPlainText('Data riset 🌱');w.vigenere.setText('KEY');w.caesar_shift.setValue(11)
    w.text_password.setText(PASSWORD);w.text_confirm.setText(PASSWORD)
    w.process_text();wait()
    assert w.export_text_button.isEnabled()
    # No extension entered: UI appends .txt.
    path=tmp_path/'export.txt'
    monkeypatch.setattr(QFileDialog,'getSaveFileName',lambda *args:(str(path.with_suffix('')),''))
    w.export_text_result();wait()
    assert path.exists()
    w.clear_text()
    assert not w.export_text_button.isEnabled()
    monkeypatch.setattr(QFileDialog,'getOpenFileName',lambda *args:(str(path),''))
    w.import_text_file();wait()
    assert w.text_mode.currentIndex()==1
    assert w.text_input.toPlainText().startswith('RVTXT2:')
    assert not w.vigenere.text() and not w.text_password.text()
    w.vigenere.setText('KEY');w.text_password.setText(PASSWORD);w.caesar_shift.setValue(11)
    w.process_text();wait()
    assert w.text_output.toPlainText()=='Data riset 🌱'
    assert not w.export_text_button.isEnabled()
    w.lock_ui('locked');w.close()
