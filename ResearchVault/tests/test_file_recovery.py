import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile
import pytest
from PIL import Image
from conftest import PASSWORD
from researchvault.crypto import seal, VaultError, canonical
from researchvault.file_io import pack_file, unpack_file


def files():
    image=Image.new('RGB',(40,30),(10,130,220))
    png=io.BytesIO();image.save(png,format='PNG')
    pdf=io.BytesIO();image.save(pdf,format='PDF')
    word=io.BytesIO()
    with zipfile.ZipFile(word,'w') as z:
        z.writestr('[Content_Types].xml','<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr('_rels/.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr('word/document.xml','<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Data asli penelitian</w:t></w:r></w:p></w:body></w:document>')
    return [('foto.png',png.getvalue()),('laporan.v1.pdf',pdf.getvalue()),('dokumen.docx',word.getvalue()),
            ('data.csv',b'nama,nilai\r\nA,1\r\n'),('Catatan α.txt','Isi asli 🌱\r\n'.encode()),
            ('tanpa_ekstensi',b'\x00\xff\x01'),('kosong.txt',b'')]


@pytest.mark.parametrize('name,data',files())
def test_original_name_bytes_and_hash_recovered(engine,tmp_path,name,data):
    source=tmp_path/name;source.write_bytes(data)
    encrypted=tmp_path/'nama_bebas.rvault'
    output=tmp_path/'hasil';output.mkdir()
    engine.file(source,encrypted,PASSWORD)
    # Filename lives inside encrypted payload, not a plaintext outer header.
    assert name.encode() not in encrypted.read_bytes()
    source.unlink()  # Recovery must not depend on the original still existing.
    result=Path(engine.file(encrypted,output,PASSWORD,True))
    assert result.name==name
    assert result.read_bytes()==data
    assert hashlib.sha256(result.read_bytes()).digest()==hashlib.sha256(data).digest()
    if name.endswith('.png'):
        with Image.open(result) as im:im.verify()
    if name.endswith('.docx'):
        with zipfile.ZipFile(result) as z:assert z.testzip() is None and 'word/document.xml' in z.namelist()


def test_same_folder_collision_never_overwrites(engine,tmp_path):
    source=tmp_path/'asal.pdf';source.write_bytes(b'original')
    encrypted=tmp_path/'file.rvault';engine.file(source,encrypted,PASSWORD)
    source.write_bytes(b'edited after encryption')
    a=Path(engine.file(encrypted,tmp_path,PASSWORD,True))
    b=Path(engine.file(encrypted,tmp_path,PASSWORD,True))
    assert a!=b and a!=source and a.suffix=='.pdf'
    assert a.read_bytes()==b.read_bytes()==b'original'
    assert source.read_bytes()==b'edited after encryption'


def test_explicit_target_extension(engine,tmp_path):
    source=tmp_path/'laporan.v1.pdf';source.write_bytes(b'payload')
    encrypted=tmp_path/'e.rvault';engine.file(source,encrypted,PASSWORD)
    result=Path(engine.file(encrypted,tmp_path/'hasil',PASSWORD,True))
    assert result.name=='hasil.pdf'
    assert Path(engine.file(encrypted,tmp_path/'salinan.pdf',PASSWORD,True)).read_bytes()==b'payload'
    with pytest.raises(VaultError,match='Ekstensi'):engine.file(encrypted,tmp_path/'wrong.rvault',PASSWORD,True)
    assert not (tmp_path/'wrong.rvault').exists()


def test_legacy_file_needs_original_extension(engine,tmp_path):
    encrypted=tmp_path/'dokumen.rvault';encrypted.write_bytes(seal(b'%PDF-old',PASSWORD,'file'))
    output=tmp_path/'hasil';output.mkdir()
    with pytest.raises(VaultError,match='File lama'):engine.file(encrypted,output,PASSWORD,True)
    assert list(output.iterdir())==[]
    result=Path(engine.file(encrypted,output,PASSWORD,True,'.pdf'))
    assert result.name=='dokumen.pdf' and result.read_bytes()==b'%PDF-old'
    # An explicitly named output still works for older API callers.
    assert Path(engine.file(encrypted,tmp_path/'manual.pdf',PASSWORD,True)).read_bytes()==b'%PDF-old'


def test_legacy_preserved_name(engine,tmp_path):
    encrypted=tmp_path/'laporan.pdf.rvault';encrypted.write_bytes(seal(b'old bytes',PASSWORD,'file'))
    out=tmp_path/'out';out.mkdir()
    assert Path(engine.file(encrypted,out,PASSWORD,True)).name=='laporan.pdf'


@pytest.mark.parametrize('fault',['password','tamper','truncate'])
def test_auth_failure_no_plaintext(engine,tmp_path,fault):
    source=tmp_path/'s.pdf';source.write_bytes(b'secret')
    encrypted=tmp_path/'e.rvault';engine.file(source,encrypted,PASSWORD)
    raw=encrypted.read_bytes()
    if fault=='tamper':encrypted.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
    if fault=='truncate':encrypted.write_bytes(raw[:-20])
    out=tmp_path/'out';out.mkdir()
    with pytest.raises(VaultError):engine.file(encrypted,out,PASSWORD+'x' if fault=='password' else PASSWORD,True)
    assert list(out.iterdir())==[]


@pytest.mark.parametrize('name',['../outside.pdf','C:\\outside.pdf','/outside.pdf','CON','x/evil.pdf'])
def test_unsafe_metadata_no_file(engine,tmp_path,name):
    raw=b'x';meta=canonical(dict(name=name,size=1,sha256=hashlib.sha256(raw).hexdigest()))
    payload=b'RVP2'+struct.pack('>I',len(meta))+meta+raw
    encrypted=tmp_path/'e.rvault';encrypted.write_bytes(seal(payload,PASSWORD,'file-v2'))
    out=tmp_path/'out';out.mkdir()
    with pytest.raises(VaultError):engine.file(encrypted,out,PASSWORD,True)
    assert list(out.iterdir())==[]


def test_metadata_hash_mismatch():
    payload=pack_file(b'abc','data.txt')
    with pytest.raises(VaultError):unpack_file(payload[:-1]+b'd')


def test_ui_file_roundtrip_and_mode_reset(engine,tmp_path,monkeypatch):
    import time
    from PySide6.QtWidgets import QApplication,QFileDialog,QMessageBox
    from researchvault.ui import MainWindow
    app=QApplication.instance() or QApplication([])
    w=MainWindow(engine);w.timer.stop();w.root.setCurrentIndex(1);w.pages.setCurrentIndex(2)
    errors=[]
    monkeypatch.setattr(QMessageBox,'warning',lambda *a:errors.append(a[-1]))
    source=tmp_path/'research.pdf';source.write_bytes(b'%PDF-source')
    w.file_source.setText(str(source));w.file_target.setText(str(tmp_path/'encrypted'))
    w.file_password.setText(PASSWORD);w.file_confirm.setText(PASSWORD)
    def wait():
        until=time.monotonic()+20
        while w.busy and time.monotonic()<until:app.processEvents();time.sleep(.01)
        app.processEvents();assert not w.busy and not errors
    w.process_file();wait()
    encrypted=tmp_path/'encrypted.rvault';assert encrypted.exists()
    w.file_mode.setCurrentIndex(1)
    assert not w.file_target.text() and not w.file_password.text()
    w.file_source.setText(str(encrypted))
    out=tmp_path/'results';out.mkdir()
    monkeypatch.setattr(QFileDialog,'getExistingDirectory',lambda *a:str(out))
    w.choose_file_target();w.file_password.setText(PASSWORD);w.process_file();wait()
    assert (out/'research.pdf').read_bytes()==source.read_bytes()
    assert str(out/'research.pdf') in w.file_result.text()
    w.lock_ui('end');w.close()
