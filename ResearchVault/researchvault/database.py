import sqlite3
from pathlib import Path
from uuid import uuid4
from contextlib import contextmanager

SCHEMA = '''
PRAGMA user_version=2;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, windows_sid TEXT NOT NULL,
 keystore BLOB NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dongles (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), fingerprint TEXT NOT NULL,
 secret BLOB NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','revoked')),
 created_at TEXT NOT NULL, UNIQUE(user_id,fingerprint));
CREATE TABLE IF NOT EXISTS secure_notes (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 ciphertext BLOB NOT NULL CHECK(length(ciphertext)>=16), nonce BLOB NOT NULL CHECK(length(nonce)=12),
 revision INTEGER NOT NULL CHECK(revision>0), created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(user_id,nonce));
CREATE TABLE IF NOT EXISTS blockchain_blocks (
 user_id TEXT NOT NULL REFERENCES users(id), chain_index INTEGER NOT NULL CHECK(chain_index>=0),
 payload TEXT NOT NULL, current_hash TEXT NOT NULL CHECK(length(current_hash)=64),
 PRIMARY KEY(user_id,chain_index));
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY, user_id TEXT REFERENCES users(id), event_type TEXT NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN ('success','failure')), timestamp TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS artifacts (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), kind TEXT NOT NULL,
 output_path TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS notes_owner ON secure_notes(user_id,updated_at);
'''


class Database:
    def __init__(self, path):
        self.path = Path(path)
        with self.connect() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1, 2):
                raise RuntimeError('Versi database tidak didukung.')
            if version == 1:
                self._migrate_v1(db)
            db.executescript(SCHEMA)

    def _migrate_v1(self, db):
        # Preserve a consistent SQLite backup before removing the SID uniqueness
        # constraint. DPAPI and per-login SID checks still apply to each account.
        backup = self.path.with_name('vault-before-v2-' + uuid4().hex + '.db')
        with sqlite3.connect(backup) as destination:
            db.backup(destination)
        db.execute('PRAGMA foreign_keys=OFF')
        try:
            db.execute('BEGIN IMMEDIATE')
            db.execute("""CREATE TABLE users_v2 (
                id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL, windows_sid TEXT NOT NULL,
                keystore BLOB NOT NULL, created_at TEXT NOT NULL)""")
            db.execute('INSERT INTO users_v2 SELECT * FROM users')
            db.execute('DROP TABLE users')
            db.execute('ALTER TABLE users_v2 RENAME TO users')
            if db.execute('PRAGMA foreign_key_check').fetchall():
                raise RuntimeError('Migrasi dibatalkan: relasi database tidak konsisten.')
            db.execute('PRAGMA user_version=2')
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.execute('PRAGMA foreign_keys=ON')

    @contextmanager
    def connect(self, write=False):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            if write:
                db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
