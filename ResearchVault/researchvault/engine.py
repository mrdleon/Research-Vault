"""Application services with session guards, transactions and real access factors."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from .crypto import (VaultError, canonical, b64, unb64, password_check, seal,
                     open_envelope, encrypt_text, decrypt_text, MAX_FILE, MAX_ENVELOPE, MAX_NOTE)
from .storage import read_limited, atomic_new, file_hash
from .database import Database
from . import stego
from .file_io import pack_file, decrypt_file, recovery_target
from .text_io import validate_text_export, MAX_TEXT_EXPORT


def now():
    return datetime.now(timezone.utc).isoformat()


def uid():
    return str(uuid.uuid4())


def block_hash(payload):
    return hashlib.sha256(canonical(payload)).hexdigest()


class Engine:
    def __init__(self, directory, platform):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db = Database(self.directory / 'vault.db')
        self.platform = platform
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
        self.mutex = threading.RLock()
        self.user = None
        self.master = None
        self.notes_key = None
        self.active_dongle = None
        self.generation = 0
        self.last_activity = 0
        self.timeout = 300
        self.failures = 0
        self.retry_after = 0

    def initialized(self):
        with self.db.connect() as db:
            return db.execute('SELECT 1 FROM users').fetchone() is not None

    def lock(self):
        with self.mutex:
            self.generation += 1
            self.user = self.master = self.notes_key = self.active_dongle = None

    def touch(self):
        with self.mutex:
            if self.user and time.monotonic()-self.last_activity < self.timeout:
                self.last_activity = time.monotonic()

    def _token(self, device):
        try:
            data = json.loads(read_limited(Path(device['root']) / 'ResearchVault.token', 2048))
            if set(data) != {'version', 'id', 'secret'} or data['version'] != 1 or len(unb64(data['secret'])) != 32:
                raise ValueError()
            return data
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise VaultError('Token USB tidak ditemukan atau rusak.') from exc

    def _dongle(self, user_id, required_id=None):
        with self.db.connect() as db:
            rows = db.execute("SELECT * FROM dongles WHERE user_id=? AND status='active'", (user_id,)).fetchall()
        devices = self.platform.devices()
        for row in rows:
            if required_id and row['id'] != required_id:
                continue
            for device in devices:
                if device['fingerprint'] != row['fingerprint']:
                    continue
                try:
                    token = self._token(device)
                    challenge = os.urandom(32)
                    context = b'ResearchVault/dongle/v1/' + row['id'].encode() + challenge
                    expected = hmac.digest(self.platform.unprotect(row['secret']), context, 'sha256')
                    actual = hmac.digest(unb64(token['secret']), context, 'sha256')
                    if token['id'] == row['id'] and hmac.compare_digest(expected, actual):
                        return row['id']
                except VaultError:
                    continue
        raise VaultError('Dongle terdaftar tidak terhubung atau tokennya tidak cocok.')

    def guard(self, generation=None):
        with self.mutex:
            if generation is not None and generation != self.generation:
                raise VaultError('Operasi berasal dari sesi yang sudah berakhir.')
            if self.user is None or time.monotonic()-self.last_activity >= self.timeout:
                self.lock()
                raise VaultError('Sesi terkunci. Silakan masuk kembali.')
            try:
                self._dongle(self.user['id'], self.active_dongle)
                if self.platform.sid() != self.user['windows_sid']:
                    raise VaultError('Akun Windows berbeda.')
            except Exception:
                self.lock()
                raise
            return self.generation

    @contextmanager
    def commit_guard(self, generation):
        with self.mutex:
            self.guard(generation)
            yield

    def _audit(self, db, event, success=True, user_id=None):
        db.execute('INSERT INTO audit_logs(user_id,event_type,outcome,timestamp) VALUES(?,?,?,?)',
                   (user_id or (self.user['id'] if self.user else None), event,
                    'success' if success else 'failure', now()))

    def _device(self, fingerprint):
        matches = [x for x in self.platform.devices() if x['fingerprint'] == fingerprint]
        if len(matches) != 1:
            raise VaultError('USB tidak tersedia atau identitasnya ambigu.')
        return matches[0]

    def register(self, username, name, password, fingerprint, hwnd):
        if self.user is not None:
            raise VaultError('Kunci vault sebelum mendaftarkan akun baru.')
        username = username.strip().lower()
        if not re.fullmatch(r'[a-z0-9_.-]{3,40}', username) or not 1 <= len(name.strip()) <= 80:
            raise VaultError('Username 3–40 huruf/angka/titik/garis; nama wajib diisi (maks. 80).')
        password_check(password)
        with self.db.connect() as db:
            if db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                raise VaultError('Username sudah digunakan. Pilih username lain atau masuk.')
        device = self._device(fingerprint)
        token_path = Path(device['root']) / 'ResearchVault.token'
        if token_path.exists():
            raise VaultError('USB sudah berisi token. Gunakan USB kosong lain; token lama tidak ditimpa.')
        self.platform.hello(hwnd)
        device = self._device(fingerprint)
        user_id, token_id, secret = uid(), uid(), os.urandom(32)
        sid, created = self.platform.sid(), now()
        hashed = self.hasher.hash(password)
        wrapped = self.platform.protect(seal(os.urandom(32), password, 'master'))
        protected_secret = self.platform.protect(secret)
        token_written = False
        try:
            with self.db.connect(write=True) as db:
                if db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                    raise VaultError('Username sudah digunakan. Pilih username lain atau masuk.')
                db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                           (user_id, username, name.strip(), hashed, sid, wrapped, created))
                db.execute('INSERT INTO dongles VALUES(?,?,?,?,?,?)',
                           (token_id, user_id, fingerprint, protected_secret, 'active', created))
                genesis = dict(v=1, index=0, timestamp=created, user_id=user_id,
                               asset_id=None, name=None, file_hash=None, previous_hash='0'*64)
                db.execute('INSERT INTO blockchain_blocks VALUES(?,?,?,?)',
                           (user_id, 0, canonical(genesis).decode(), block_hash(genesis)))
                self._audit(db, 'register', user_id=user_id)
                atomic_new(token_path, canonical(dict(version=1, id=token_id, secret=b64(secret))))
                token_written = True
        except BaseException:
            if token_written:
                token_path.unlink(missing_ok=True)
            raise

    def login(self, username, password, hwnd):
        self.lock()
        generation = self.generation
        if time.monotonic() < self.retry_after:
            raise VaultError('Tunggu beberapa detik sebelum mencoba kembali.')
        try:
            with self.db.connect() as db:
                user = db.execute('SELECT * FROM users WHERE username=?', (username.strip().lower(),)).fetchone()
            if not user or self.platform.sid() != user['windows_sid']:
                raise VaultError('Kredensial tidak sesuai.')
            dongle_id = self._dongle(user['id'])
            self.platform.hello(hwnd)
            password_check(password)
            self.hasher.verify(user['password_hash'], password)
            master = open_envelope(self.platform.unprotect(user['keystore']), password, 'master')
            if len(master) != 32:
                raise VaultError('Master key rusak.')
            self._dongle(user['id'], dongle_id)
            with self.mutex:
                if generation != self.generation:
                    raise VaultError('Login dibatalkan karena sesi berubah.')
                self.user = dict(user)
                self.master = master
                self.notes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                      info=b'researchvault/notes/v1').derive(master)
                self.active_dongle = dongle_id
                self.last_activity = time.monotonic()
                self.failures = 0
                with self.db.connect(write=True) as db:
                    self._audit(db, 'login')
            return self.user['display_name']
        except Exception as exc:
            self.lock()
            self.failures += 1
            self.retry_after = time.monotonic() + min(30, 2 ** min(self.failures, 5))
            with self.db.connect(write=True) as db:
                self._audit(db, 'login', False)
            if isinstance(exc, (VerificationError, InvalidHashError)):
                raise VaultError('Kredensial tidak sesuai.') from exc
            raise

    def text(self, value, key, password, decrypt=False, shift=3):
        generation = self.guard()
        result = (decrypt_text if decrypt else encrypt_text)(value, key, password, shift)
        self.guard(generation)
        return result

    def export_text(self, value, target):
        generation = self.guard()
        if Path(target).suffix.lower() != '.txt':
            raise VaultError('Gunakan ekstensi .txt untuk ekspor teks terenkripsi.')
        value = validate_text_export(value)
        with self.commit_guard(generation):
            atomic_new(target, value.encode('utf-8'), lambda: self.guard(generation))
        return str(target)

    def import_text(self, source):
        generation = self.guard()
        raw = read_limited(source, MAX_TEXT_EXPORT + 3)
        try:
            value = raw.decode('utf-8-sig')
        except UnicodeError as exc:
            raise VaultError('File harus berupa teks UTF-8 dengan awalan RVTXT1: atau RVTXT2:.') from exc
        result = validate_text_export(value)
        self.guard(generation)
        return result

    def file(self, source, target, password, decrypt=False, legacy_extension=""):
        generation = self.guard()
        if Path(source).resolve() == Path(target).resolve():
            raise VaultError('Sumber dan tujuan harus berbeda.')
        raw = read_limited(source, MAX_ENVELOPE if decrypt else MAX_FILE)
        if decrypt:
            result, original_name = decrypt_file(raw, password)
            target = recovery_target(target, source, original_name, legacy_extension.strip())
            if Path(source).resolve() == Path(target).resolve():
                raise VaultError('Sumber dan tujuan harus berbeda.')
        else:
            result = seal(pack_file(raw, Path(source).name), password, 'file-v2')
        with self.commit_guard(generation):
            atomic_new(target, result, lambda: self.guard(generation))
            with self.db.connect(write=True) as db:
                db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?)',
                           (uid(), self.user['id'], 'file-decrypt' if decrypt else 'file-encrypt', str(target), now()))
                self._audit(db, 'file-decrypt' if decrypt else 'file-encrypt')
        return str(target)

    def image(self, source, password, text=None, target=None):
        generation = self.guard()
        if text is None:
            result = stego.extract(source, password)
            self.guard(generation)
            return result
        if not target or Path(target).suffix.lower() != '.png' or Path(target).resolve() == Path(source).resolve():
            raise VaultError('Pilih nama PNG baru untuk hasil.')
        result = stego.embed(source, text, password)
        with self.commit_guard(generation):
            atomic_new(target, result, lambda: self.guard(generation))
            with self.db.connect(write=True) as db:
                db.execute('INSERT INTO artifacts VALUES(?,?,?,?,?)', (uid(), self.user['id'], 'stego', str(target), now()))
                self._audit(db, 'stego-embed')
        return str(target)

    def _aad(self, note_id, revision):
        return canonical(dict(domain='ResearchVault/notes/v1', user_id=self.user['id'], note_id=note_id, revision=revision))

    def notes(self):
        generation = self.guard()
        with self.commit_guard(generation):
            with self.db.connect() as db:
                rows = db.execute('SELECT * FROM secure_notes WHERE user_id=? ORDER BY updated_at DESC', (self.user['id'],)).fetchall()
            result = []
            try:
                for row in rows:
                    plain = AESGCM(self.notes_key).decrypt(row['nonce'], row['ciphertext'], self._aad(row['id'], row['revision']))
                    payload = json.loads(plain)
                    result.append(dict(id=row['id'], title=payload['title'], body=payload['body'], revision=row['revision']))
            except (InvalidTag, ValueError, KeyError) as exc:
                raise VaultError('Integritas catatan gagal. Periksa cadangan database.') from exc
        self.guard(generation)
        return result

    def save_note(self, title, body, note_id=None, expected_revision=None):
        generation = self.guard()
        if not title.strip() or len(title) > 200:
            raise VaultError('Judul wajib diisi, maksimal 200 karakter.')
        payload = canonical(dict(title=title, body=body))
        if len(payload) > MAX_NOTE:
            raise VaultError('Catatan maksimal 1 MiB termasuk judul.')
        with self.commit_guard(generation):
            with self.db.connect(write=True) as db:
                if note_id:
                    row = db.execute('SELECT * FROM secure_notes WHERE id=? AND user_id=?', (note_id, self.user['id'])).fetchone()
                    if not row or row['revision'] != expected_revision:
                        raise VaultError('Catatan berubah atau tidak ditemukan. Muat ulang.')
                    revision, created = row['revision']+1, row['created_at']
                else:
                    note_id, revision, created = uid(), 1, now()
                for _ in range(10):
                    nonce = os.urandom(12)
                    if not db.execute('SELECT 1 FROM secure_notes WHERE user_id=? AND nonce=?', (self.user['id'], nonce)).fetchone():
                        break
                else:
                    raise VaultError('Gagal membuat nonce unik.')
                ciphertext = AESGCM(self.notes_key).encrypt(nonce, payload, self._aad(note_id, revision))
                db.execute('INSERT INTO secure_notes VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET ciphertext=excluded.ciphertext, nonce=excluded.nonce, revision=excluded.revision, updated_at=excluded.updated_at',
                           (note_id, self.user['id'], ciphertext, nonce, revision, created, now()))
                self._audit(db, 'note-save')
        return note_id

    def delete_note(self, note_id):
        generation = self.guard()
        with self.commit_guard(generation):
            with self.db.connect(write=True) as db:
                db.execute('DELETE FROM secure_notes WHERE id=? AND user_id=?', (note_id, self.user['id']))
                self._audit(db, 'note-delete')

    def _blocks(self, db):
        rows = db.execute('SELECT * FROM blockchain_blocks WHERE user_id=? ORDER BY chain_index', (self.user['id'],)).fetchall()
        if not rows:
            raise VaultError('Genesis tidak ditemukan.')
        result, previous = [], '0'*64
        for i, row in enumerate(rows):
            try:
                data = json.loads(row['payload'])
                if (set(data) != {'v','index','timestamp','user_id','asset_id','name','file_hash','previous_hash'}
                        or data['index'] != i or row['chain_index'] != i or data['v'] != 1
                        or data['user_id'] != self.user['id'] or data['previous_hash'] != previous
                        or block_hash(data) != row['current_hash']):
                    raise ValueError()
                if i == 0:
                    if any(data[x] is not None for x in ('asset_id', 'name', 'file_hash')):
                        raise ValueError()
                elif (not isinstance(data['name'], str) or not data['name']
                      or not isinstance(data['asset_id'], str) or not data['asset_id']
                      or not re.fullmatch('[0-9a-f]{64}', data['file_hash'] or '')):
                    raise ValueError()
                previous = row['current_hash']
                result.append(dict(**data, current_hash=previous))
            except (ValueError, KeyError, TypeError) as exc:
                raise VaultError(f'Rantai tidak konsisten pada blok {i}.') from exc
        return result

    def blocks(self):
        generation = self.guard()
        with self.commit_guard(generation):
            with self.db.connect() as db:
                return self._blocks(db)

    def register_asset(self, path, name):
        generation = self.guard()
        if not name.strip() or len(name) > 200:
            raise VaultError('Alias aset wajib diisi, maksimal 200 karakter.')
        digest = file_hash(path)
        with self.commit_guard(generation):
            with self.db.connect(write=True) as db:
                blocks = self._blocks(db)
                payload = dict(v=1, index=len(blocks), timestamp=now(), user_id=self.user['id'],
                               asset_id=uid(), name=name.strip(), file_hash=digest,
                               previous_hash=blocks[-1]['current_hash'])
                db.execute('INSERT INTO blockchain_blocks VALUES(?,?,?,?)',
                           (self.user['id'], len(blocks), canonical(payload).decode(), block_hash(payload)))
                self._audit(db, 'asset-register')
        return digest

    def verify_asset(self, index, path):
        generation = self.guard()
        blocks = self.blocks()
        if not 0 < index < len(blocks):
            raise VaultError('Pilih blok aset, bukan genesis.')
        result = hmac.compare_digest(file_hash(path), blocks[index]['file_hash'])
        self.guard(generation)
        return result

    def summary(self):
        generation = self.guard()
        with self.commit_guard(generation):
            with self.db.connect() as db:
                user_id = self.user['id']
                counts = [db.execute(query, (user_id,)).fetchone()[0] for query in (
                    'SELECT count(*) FROM secure_notes WHERE user_id=?',
                    "SELECT count(*) FROM artifacts WHERE user_id=? AND kind='file-encrypt'",
                    'SELECT count(*)-1 FROM blockchain_blocks WHERE user_id=?')]
                logs = [dict(r) for r in db.execute('SELECT event_type,outcome,timestamp FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 12', (user_id,))]
                dongles = [dict(r) for r in db.execute('SELECT id,fingerprint,status FROM dongles WHERE user_id=?', (user_id,))]
        return dict(counts=counts, logs=logs, dongles=dongles)

    def reauthenticate(self, password, hwnd):
        generation = self.guard()
        try:
            self.hasher.verify(self.user['password_hash'], password)
        except (VerificationError, InvalidHashError) as exc:
            raise VaultError('Kredensial tidak sesuai.') from exc
        self.platform.hello(hwnd)
        self.guard(generation)
        return generation

    def change_password(self, old, new, hwnd):
        password_check(new)
        generation = self.reauthenticate(old, hwnd)
        with self.mutex:
            master = self.master
        wrapped = self.platform.protect(seal(master, new, 'master'))
        hashed = self.hasher.hash(new)
        with self.commit_guard(generation):
            with self.db.connect(write=True) as db:
                db.execute('UPDATE users SET password_hash=?,keystore=? WHERE id=?', (hashed, wrapped, self.user['id']))
                self._audit(db, 'password-change')
            self.user.update(password_hash=hashed, keystore=wrapped)

    def add_dongle(self, fingerprint, password, hwnd):
        generation = self.reauthenticate(password, hwnd)
        device = self._device(fingerprint)
        token_id, secret = uid(), os.urandom(32)
        path = Path(device['root']) / 'ResearchVault.token'
        written = False
        try:
            with self.commit_guard(generation):
                with self.db.connect(write=True) as db:
                    db.execute('INSERT INTO dongles VALUES(?,?,?,?,?,?)',
                               (token_id, self.user['id'], fingerprint, self.platform.protect(secret), 'active', now()))
                    atomic_new(path, canonical(dict(version=1, id=token_id, secret=b64(secret))))
                    written = True
                    self._audit(db, 'dongle-add')
        except BaseException:
            if written:
                path.unlink(missing_ok=True)
            raise

    def revoke_dongle(self, token_id, password, hwnd):
        generation = self.reauthenticate(password, hwnd)
        with self.commit_guard(generation):
            with self.db.connect(write=True) as db:
                count = db.execute("SELECT count(*) FROM dongles WHERE user_id=? AND status='active'", (self.user['id'],)).fetchone()[0]
                if count <= 1:
                    raise VaultError('Daftarkan dongle cadangan sebelum mencabut dongle terakhir.')
                db.execute("UPDATE dongles SET status='revoked' WHERE id=? AND user_id=?", (token_id, self.user['id']))
                self._audit(db, 'dongle-revoke')
            if token_id == self.active_dongle:
                self.lock()

    def profile(self, name):
        generation = self.guard()
        if not 1 <= len(name.strip()) <= 80:
            raise VaultError('Nama wajib diisi, maksimal 80 karakter.')
        with self.commit_guard(generation):
            with self.db.connect(write=True) as db:
                db.execute('UPDATE users SET display_name=? WHERE id=?', (name.strip(), self.user['id']))
            self.user['display_name'] = name.strip()

    def backup(self, target, password, hwnd):
        generation = self.reauthenticate(password, hwnd)
        # Database contains DPAPI-protected key store in the SAME transaction domain.
        with self.commit_guard(generation):
            temporary = self.directory / ('backup-' + uid() + '.db')
            try:
                with self.db.connect() as source:
                    destination = sqlite3.connect(temporary)
                    try:
                        source.backup(destination)
                    finally:
                        destination.close()
                atomic_new(target, temporary.read_bytes(), lambda: self.guard(generation))
            finally:
                temporary.unlink(missing_ok=True)
        return str(target)
