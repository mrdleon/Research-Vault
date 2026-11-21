"""Upgrade regression tests: four layers, legacy transport, accounts and migration."""
import json
import sqlite3
import struct
from pathlib import Path
import pytest
from conftest import PASSWORD
from researchvault import crypto
from researchvault.crypto import VaultError
from researchvault.database import Database, SCHEMA
from researchvault.engine import Engine
from researchvault.text_io import validate_text_export


def test_caesar_known_vector():
    assert crypto.caesar('Abc XYZ! é🌱 123', 3) == 'Def ABC! é🌱 123'
    assert crypto.caesar('Def ABC! é🌱 123', 3, True) == 'Abc XYZ! é🌱 123'


@pytest.mark.parametrize('shift', [0, 26, -1, 1.5, True, '3', None])
def test_invalid_caesar(shift):
    with pytest.raises(VaultError): crypto.encrypt_text('test', 'KEY', PASSWORD, shift)


@pytest.mark.parametrize('shift', [1, 3, 25])
def test_four_layers_and_reverse_order(shift):
    message = 'Attack at dawn! αβ 🌱\n123'
    value = crypto.encrypt_text(message, 'LEMON', PASSWORD, shift)
    assert value.startswith('RVTXT2:')
    info, header, ciphertext = crypto.parse_text_v2(value)
    aes, chacha = crypto._text_keys(PASSWORD, crypto.unb64(info['salt']))
    assert aes != chacha
    inner = crypto.ChaCha20Poly1305(chacha).decrypt(
        crypto.unb64(info['chacha_nonce']), ciphertext, b'RVTXT2/CHACHA/'+header)
    content = json.loads(crypto.AESGCM(aes).decrypt(
        crypto.unb64(info['aes_nonce']), inner, b'RVTXT2/AES/'+header))
    assert content['text'] == crypto.vigenere(crypto.caesar(message, shift), 'LEMON')
    assert crypto.decrypt_text(value, 'lemon', PASSWORD, shift) == message
    assert 'shift' not in info and 'commitment' not in info


def test_wrong_caesar_and_equivalent_classic_keys():
    value = crypto.encrypt_text('message', 'B', PASSWORD, 3)
    with pytest.raises(VaultError): crypto.decrypt_text(value, 'B', PASSWORD, 4)
    # Caesar 2 plus Vigenere C has the same shift as Caesar 3 plus B;
    # encrypted commitment still requires the original input pair.
    with pytest.raises(VaultError): crypto.decrypt_text(value, 'C', PASSWORD, 2)


def repack(info, ciphertext):
    header = crypto.canonical(info)
    return 'RVTXT2:'+crypto.b64(b'RVT2'+struct.pack('>I', len(header))+header+ciphertext)


@pytest.mark.parametrize('part', ['outer', 'inner', 'nonce', 'salt'])
def test_authenticated_tampering(part):
    value = crypto.encrypt_text('secret', 'KEY', PASSWORD, 9)
    info, header, ciphertext = crypto.parse_text_v2(value)
    if part == 'outer':
        ciphertext = ciphertext[:-1]+bytes([ciphertext[-1]^1])
    elif part == 'inner':
        # Authenticate the changed inner ciphertext with a valid outer tag:
        # the AES layer must independently detect corruption.
        aes, chacha = crypto._text_keys(PASSWORD, crypto.unb64(info['salt']))
        cipher = crypto.ChaCha20Poly1305(chacha)
        inner = cipher.decrypt(crypto.unb64(info['chacha_nonce']), ciphertext, b'RVTXT2/CHACHA/'+header)
        inner = inner[:-1]+bytes([inner[-1]^1])
        ciphertext = cipher.encrypt(crypto.unb64(info['chacha_nonce']), inner, b'RVTXT2/CHACHA/'+header)
    else:
        key = 'aes_nonce' if part == 'nonce' else 'salt'
        raw = crypto.unb64(info[key]);info[key]=crypto.b64(bytes([raw[0]^1])+raw[1:])
    with pytest.raises(VaultError): crypto.decrypt_text(repack(info, ciphertext), 'KEY', PASSWORD, 9)


@pytest.mark.parametrize('field,value', [('kdf','huge-cost'), ('v', 3), ('pipeline', ['AES-256-GCM']),
                                        ('keys','other'), ('length', True), ('aes_nonce','AAAA')])
def test_reject_bad_header_before_kdf(field, value, monkeypatch):
    original = crypto.encrypt_text('secret', 'KEY', PASSWORD)
    info, _, ciphertext = crypto.parse_text_v2(original)
    info[field] = value
    def forbidden(*args): raise AssertionError('KDF must not run on invalid structure')
    monkeypatch.setattr(crypto, 'derive', forbidden)
    with pytest.raises(VaultError): crypto.decrypt_text(repack(info,ciphertext),'KEY',PASSWORD)


def test_legacy_fixture_and_transport(engine, tmp_path):
    # Fixture produced by the original released v1 crypto.py, not by v2.
    value = (Path(__file__).parent/'fixtures'/'legacy_rvtxt1.txt').read_text().strip()
    assert validate_text_export(value) == value
    assert crypto.decrypt_text(value, 'LEMON', PASSWORD, 25) == 'Pesan lama 🌱\nTetap terbaca!'
    path=tmp_path/'legacy.txt';engine.export_text(value,path)
    assert engine.text(engine.import_text(path),'LEMON',PASSWORD,True,25) == 'Pesan lama 🌱\nTetap terbaca!'
    with pytest.raises(VaultError): crypto.decrypt_text(value,'WRONG',PASSWORD)


def test_text_boundary_and_empty():
    for message in ['', 'é'*(crypto.MAX_TEXT//2)]:
        value=crypto.encrypt_text(message,'KEY',PASSWORD,25)
        assert crypto.decrypt_text(value,'KEY',PASSWORD,25)==message
    with pytest.raises(VaultError): crypto.encrypt_text('x'*(crypto.MAX_TEXT+1),'KEY',PASSWORD)


def new_device(tmp_path, platform):
    root=tmp_path/'second-usb';root.mkdir()
    device=dict(root=str(root),fingerprint='SECOND',label='Second USB')
    original=platform.device
    platform.devices=lambda:[original,device]
    return device


def test_multiple_accounts_isolated(engine, platform, tmp_path):
    first=engine.user['id'];master=engine.master
    note=engine.save_note('first title','first body')
    source=tmp_path/'asset';source.write_text('data')
    engine.register_asset(source,'first asset')
    device=new_device(tmp_path,platform)
    engine.lock()
    engine.register('dimas','Dimas',PASSWORD,device['fingerprint'],1)
    assert engine.user is None
    engine.login('dimas',PASSWORD,1)
    assert engine.user['id']!=first and engine.master!=master
    assert engine.notes()==[] and len(engine.blocks())==1
    with pytest.raises(VaultError):engine.save_note('changed','bad',note,1)
    engine.delete_note(note)
    engine.save_note('second title','second body')
    engine.lock();engine.login('marvel',PASSWORD,1)
    assert engine.notes()[0]['body']=='first body'
    assert len(engine.blocks())==2
    # A second user's token is not accepted as the first user's dongle.
    engine.lock();platform.devices=lambda:[device]
    with pytest.raises(VaultError):engine.login('marvel',PASSWORD,1)


def test_duplicate_username_preserves_token(engine,platform,tmp_path):
    token=Path(platform.device['root'])/'ResearchVault.token';original=token.read_bytes()
    device=new_device(tmp_path,platform);engine.lock()
    with pytest.raises(VaultError, match='Username sudah'):engine.register('MARVEL','Other',PASSWORD,'SECOND',1)
    assert token.read_bytes()==original
    assert not (Path(device['root'])/'ResearchVault.token').exists()


def test_register_cancelled_hello_no_account(engine,platform,tmp_path):
    device=new_device(tmp_path,platform);engine.lock();platform.allow_hello=False
    with pytest.raises(VaultError):engine.register('dimas','Dimas',PASSWORD,'SECOND',1)
    with engine.db.connect() as db:assert db.execute('SELECT count(*) FROM users').fetchone()[0]==1
    assert not (Path(device['root'])/'ResearchVault.token').exists()


def test_register_existing_usb_preserved(engine,platform):
    token=Path(platform.device['root'])/'ResearchVault.token';original=token.read_bytes();engine.lock()
    with pytest.raises(VaultError,match='token'):engine.register('dimas','Dimas',PASSWORD,'TEST-USB-1',1)
    assert token.read_bytes()==original


def test_migrate_real_v1_schema_preserves_all_rows(engine,platform,tmp_path):
    engine.save_note('old title','old content')
    src=tmp_path/'original';src.write_text('asset')
    engine.register_asset(src,'old asset')
    # Copy data into the exact original schema (UNIQUE windows_sid, version 1).
    target=tmp_path/'v1';target.mkdir();path=target/'vault.db'
    old_schema=SCHEMA.replace('user_version=2','user_version=1').replace('windows_sid TEXT NOT NULL,','windows_sid TEXT NOT NULL UNIQUE,')
    with sqlite3.connect(path) as db:
        db.executescript(old_schema)
        with engine.db.connect() as source:
            for table in ['users','dongles','secure_notes','blockchain_blocks','audit_logs','artifacts']:
                rows=source.execute('SELECT * FROM '+table).fetchall()
                for row in rows:db.execute('INSERT INTO '+table+' VALUES('+','.join('?' for _ in row)+')',tuple(row))
    engine.lock()
    migrated=Engine(target,platform)
    with migrated.db.connect() as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==2
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
    backups=list(target.glob('vault-before-v2-*.db'));assert len(backups)==1
    with sqlite3.connect(backups[0]) as db:assert db.execute('PRAGMA user_version').fetchone()[0]==1
    migrated.login('marvel',PASSWORD,1)
    assert migrated.notes()[0]['body']=='old content' and migrated.verify_asset(1,src)
    migrated.lock();device=new_device(tmp_path,platform)
    migrated.register('dimas','Dimas',PASSWORD,'SECOND',1)
    migrated.login('dimas',PASSWORD,1);assert migrated.notes()==[]
    Engine(target,platform)
    assert len(list(target.glob('vault-before-v2-*.db')))==1


def test_ui_access_choice_and_new_registration(engine,platform,tmp_path,monkeypatch):
    import time
    from PySide6.QtWidgets import QApplication,QMessageBox
    from researchvault.ui import MainWindow
    app=QApplication.instance() or QApplication([])
    engine.lock();device=new_device(tmp_path,platform)
    errors=[]
    monkeypatch.setattr(QMessageBox,'warning',lambda *args:errors.append(args[-1]))
    monkeypatch.setattr(QMessageBox,'information',lambda *args:None)
    w=MainWindow(engine);w.timer.stop();w.show();app.processEvents()
    assert not w.access_registration and w.login_tab.isChecked()
    w.register_tab.click();assert w.access_registration and w.display_name.isVisible()
    w.username.setText('dimas');w.display_name.setText('Dimas')
    w.login_password.setText(PASSWORD);w.login_confirm.setText(PASSWORD)
    w.usb_results([device]);w.usb_combo.setCurrentIndex(0)
    def wait():
        deadline=time.monotonic()+20
        while w.busy and time.monotonic()<deadline:app.processEvents();time.sleep(.01)
        app.processEvents();assert not w.busy and not errors
    w.authenticate();wait()
    assert not w.access_registration and w.root.currentIndex()==0
    assert w.username.text()=='dimas' and not w.login_password.text()
    w.login_password.setText(PASSWORD);w.authenticate();wait()
    assert w.root.currentIndex()==1 and engine.user['username']=='dimas'
    # Drain dashboard worker before closing.
    wait();w.lock_ui('done');w.close()


def test_ui_first_run_can_choose_login(tmp_path,platform):
    from PySide6.QtWidgets import QApplication
    from researchvault.ui import MainWindow
    app=QApplication.instance() or QApplication([])
    w=MainWindow(Engine(tmp_path/'fresh',platform));w.timer.stop()
    assert w.access_registration
    w.login_tab.click();assert not w.access_registration
    w.register_tab.click();assert w.access_registration
    w.close()


def test_migration_failure_rolls_back(tmp_path):
    path=tmp_path/'vault.db'
    schema=SCHEMA.replace('user_version=2','user_version=1').replace('windows_sid TEXT NOT NULL,','windows_sid TEXT NOT NULL UNIQUE,')
    with sqlite3.connect(path) as db:
        db.executescript(schema)
        db.execute("INSERT INTO audit_logs VALUES(1,'missing-user','legacy','failure','now')")
    with pytest.raises(RuntimeError, match='Migrasi dibatalkan'):Database(path)
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0]==1
        assert db.execute('SELECT user_id FROM audit_logs').fetchone()[0]=='missing-user'
        assert 'UNIQUE' in db.execute("SELECT sql FROM sqlite_master WHERE name='users'").fetchone()[0]
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='users_v2'").fetchone() is None


def test_new_account_write_failure_preserves_existing(engine,platform,tmp_path,monkeypatch):
    note=engine.save_note('keep','keep content');old_id=engine.user['id']
    device=new_device(tmp_path,platform);engine.lock()
    def fail(*args,**kwargs):raise OSError('disk failure')
    monkeypatch.setattr('researchvault.engine.atomic_new',fail)
    with pytest.raises(OSError):engine.register('dimas','Dimas',PASSWORD,'SECOND',1)
    with engine.db.connect() as db:
        assert db.execute('SELECT id FROM users').fetchall()[0][0]==old_id
        assert db.execute('SELECT count(*) FROM users').fetchone()[0]==1
        assert db.execute('SELECT id FROM secure_notes').fetchone()[0]==note
    assert not (Path(device['root'])/'ResearchVault.token').exists()


@pytest.mark.parametrize('header', [b'[]', b'null', b'{"v":2,"v":2}', b'{'*100])
def test_invalid_v2_objects(header):
    value='RVTXT2:'+crypto.b64(b'RVT2'+struct.pack('>I',len(header))+header+b'x'*32)
    with pytest.raises(VaultError):validate_text_export(value)
    with pytest.raises(VaultError):crypto.decrypt_text(value,'KEY',PASSWORD)


def test_version_prefix_cannot_downgrade():
    value=crypto.encrypt_text('secret','KEY',PASSWORD)
    with pytest.raises(VaultError):validate_text_export('RVTXT1:'+value[7:])
    with pytest.raises(VaultError):crypto.decrypt_text('RVTXT1:'+value[7:],'KEY',PASSWORD)
