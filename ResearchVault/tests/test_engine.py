import json
import time
import pytest
from cryptography.exceptions import InvalidTag
from conftest import PASSWORD
from researchvault.crypto import VaultError, canonical
from researchvault.engine import Engine


def test_registration_and_login(engine):
    assert engine.user['username'] == 'marvel'
    assert engine.blocks()[0]['index'] == 0
    engine.lock()
    engine.login('marvel', PASSWORD, 1)
    assert engine.user


def test_duplicate_registration(engine):
    with pytest.raises(VaultError): engine.register('other', 'Other', PASSWORD, 'TEST-USB-1', 1)


def test_hello_cancelled(engine, platform):
    engine.lock()
    platform.allow_hello = False
    with pytest.raises(VaultError): engine.login('marvel', PASSWORD, 1)
    assert engine.user is None


def test_wrong_password(engine):
    with pytest.raises(VaultError): engine.login('marvel', PASSWORD+'wrong', 1)
    assert engine.user is None
    with pytest.raises(VaultError, match='Tunggu'): engine.login('marvel', PASSWORD, 1)


def test_missing_usb(engine, platform):
    platform.connected = False
    with pytest.raises(VaultError): engine.notes()
    assert engine.user is None


def test_wrong_sid(engine, platform):
    platform.identity = 'OTHER-SID'
    with pytest.raises(VaultError): engine.guard()
    assert engine.user is None


def test_token_tamper(engine, platform):
    from pathlib import Path
    p = Path(platform.device['root'])/'ResearchVault.token'
    token = json.loads(p.read_text())
    token['secret'] = 'A'*44
    p.write_text(json.dumps(token))
    with pytest.raises(VaultError): engine.guard()


def test_identity_tamper(engine, platform):
    platform.device['fingerprint'] = 'OTHER-USB'
    with pytest.raises(VaultError): engine.guard()


def test_idle_and_generation(engine):
    generation = engine.guard()
    engine.last_activity = time.monotonic() - 301
    with pytest.raises(VaultError): engine.guard(generation)
    assert engine.user is None


def test_note_crud_and_at_rest(engine):
    note_id = engine.save_note('RAHASIA-JUDUL-921', 'RAHASIA-ISI-883')
    assert engine.notes()[0]['body'] == 'RAHASIA-ISI-883'
    with engine.db.connect() as db:
        old = db.execute('SELECT nonce FROM secure_notes').fetchone()[0]
    engine.save_note('New title', 'New body', note_id, 1)
    assert engine.notes()[0]['revision'] == 2
    with engine.db.connect() as db:
        new = db.execute('SELECT nonce FROM secure_notes').fetchone()[0]
    assert old != new
    raw = engine.db.path.read_bytes()
    assert b'RAHASIA-JUDUL-921' not in raw and b'RAHASIA-ISI-883' not in raw
    assert b'New body' not in raw
    with pytest.raises(VaultError): engine.save_note('Old', 'Conflict', note_id, 1)
    engine.delete_note(note_id)
    assert engine.notes() == []


def test_note_swap_rejected(engine):
    a = engine.save_note('first', 'one')
    b = engine.save_note('second', 'two')
    with engine.db.connect(write=True) as db:
        ciphertext = db.execute('SELECT ciphertext FROM secure_notes WHERE id=?',(a,)).fetchone()[0]
        db.execute('UPDATE secure_notes SET ciphertext=? WHERE id=?',(ciphertext,b))
    with pytest.raises(VaultError): engine.notes()


def test_password_rotation_restart_and_backup(engine, tmp_path, platform):
    engine.save_note('title', 'must survive')
    new = 'New-long-password-2026!'
    engine.change_password(PASSWORD, new, 1)
    backup = tmp_path/'backup.db'
    engine.backup(backup,new,1)
    engine.lock()
    restarted = Engine(engine.directory,platform)
    restarted.login('marvel',new,1)
    assert restarted.notes()[0]['body'] == 'must survive'
    restarted.lock()
    with pytest.raises(VaultError): restarted.login('marvel',PASSWORD,1)
    assert backup.exists()


@pytest.mark.parametrize('extension', ['pdf','docx','xlsx','csv','txt','png','jpg','bin'])
def test_file_roundtrip(engine,tmp_path,extension):
    # Binary fixtures exercise byte preservation, not application-specific parsers.
    src, enc, dec = [tmp_path/x for x in (f'data.{extension}', 'export.rvault', f'restored.{extension}')]
    src.write_bytes(bytes(range(256))*8)
    engine.file(src,enc,PASSWORD)
    engine.file(enc,dec,PASSWORD,True)
    assert src.read_bytes() == dec.read_bytes()
    assert src.read_bytes() != enc.read_bytes()


def test_failed_file_no_output(engine,tmp_path):
    source, target = tmp_path/'bad.rvault',tmp_path/'plain'
    source.write_bytes(b'bad data')
    with pytest.raises(VaultError): engine.file(source,target,PASSWORD,True)
    assert not target.exists()


def test_chain_file_and_tamper(engine,tmp_path):
    source = tmp_path/'research.txt'
    source.write_text('original')
    engine.register_asset(source,'Dataset v1')
    assert engine.verify_asset(1,source)
    source.write_text('changed')
    assert not engine.verify_asset(1,source)
    assert len(engine.blocks()) == 2
    with engine.db.connect(write=True) as db:
        payload = json.loads(db.execute('SELECT payload FROM blockchain_blocks WHERE chain_index=1').fetchone()[0])
        payload['name'] = 'tampered'
        db.execute('UPDATE blockchain_blocks SET payload=? WHERE chain_index=1',(json.dumps(payload),))
    with pytest.raises(VaultError,match='blok 1'): engine.blocks()
    with pytest.raises(VaultError): engine.register_asset(source,'next')


def test_services_locked(engine,tmp_path):
    engine.lock()
    actions = [lambda:engine.text('x','KEY',PASSWORD), lambda:engine.file('x','y',PASSWORD),
               engine.notes, lambda:engine.save_note('x','y'), lambda:engine.delete_note('x'),
               lambda:engine.image('x',PASSWORD), engine.blocks, engine.summary,
               lambda:engine.register_asset('x','y'), lambda:engine.profile('name')]
    for action in actions:
        with pytest.raises(VaultError): action()


def test_bootstrap_rollback(tmp_path, platform, monkeypatch):
    e = Engine(tmp_path/'fresh',platform)
    def fail(*args,**kwargs): raise OSError('disk failure')
    monkeypatch.setattr('researchvault.engine.atomic_new',fail)
    with pytest.raises(OSError): e.register('marvel','Marvel',PASSWORD,'TEST-USB-1',1)
    assert not e.initialized()


def test_revoke_last_rejected(engine):
    with pytest.raises(VaultError): engine.revoke_dongle(engine.active_dongle,PASSWORD,1)
    assert engine.guard() is not None


def test_stale_generation_does_not_kill_new_session(engine):
    stale = engine.generation
    engine.lock()
    engine.login('marvel',PASSWORD,1)
    with pytest.raises(VaultError): engine.guard(stale)
    assert engine.user is not None


def test_file_exact_limit_and_above(engine,tmp_path):
    from researchvault.crypto import MAX_FILE
    source, encrypted, restored = tmp_path/'large.bin',tmp_path/'large.rvault',tmp_path/'restore.bin'
    source.write_bytes(b'x'*MAX_FILE)
    engine.file(source,encrypted,PASSWORD)
    engine.file(encrypted,restored,PASSWORD,True)
    assert restored.stat().st_size == MAX_FILE
    with source.open('ab') as f: f.write(b'x')
    with pytest.raises(VaultError): engine.file(source,tmp_path/'too-large.rvault',PASSWORD)


def test_usb_removed_before_output(engine,tmp_path,platform,monkeypatch):
    from researchvault import engine as module
    original = module.seal
    def remove_after_encryption(*args):
        result = original(*args)
        platform.connected = False
        return result
    monkeypatch.setattr(module,'seal',remove_after_encryption)
    source, output = tmp_path/'source',tmp_path/'output'
    source.write_bytes(b'secret')
    with pytest.raises(VaultError): engine.file(source,output,PASSWORD)
    assert not output.exists()


def test_backup_restore_same_account(engine,tmp_path,platform):
    import shutil
    engine.save_note('restore title','restore body')
    backup = tmp_path/'snapshot.db'
    engine.backup(backup,PASSWORD,1)
    restored_path = tmp_path/'restored'
    restored_path.mkdir()
    shutil.copy2(backup,restored_path/'vault.db')
    restored = Engine(restored_path,platform)
    restored.login('marvel',PASSWORD,1)
    assert restored.notes()[0]['body'] == 'restore body'


def test_dongle_backup_revocation(engine,tmp_path,platform):
    from pathlib import Path
    original_device = platform.device
    spare_dir = tmp_path/'spare';spare_dir.mkdir()
    spare = dict(root=str(spare_dir),fingerprint='SPARE',label='spare')
    platform.devices = lambda:[original_device,spare]
    old_id = engine.active_dongle
    engine.add_dongle('SPARE',PASSWORD,1)
    engine.revoke_dongle(old_id,PASSWORD,1)
    assert engine.user is None
    platform.devices = lambda:[spare]
    engine.login('marvel',PASSWORD,1)
    assert engine.active_dongle != old_id


def test_corrupt_keystore_no_login(engine):
    with engine.db.connect(write=True) as db:
        db.execute('UPDATE users SET keystore=?',(b'corrupt',))
    engine.lock()
    with pytest.raises(VaultError): engine.login('marvel',PASSWORD,1)
    assert engine.user is None
