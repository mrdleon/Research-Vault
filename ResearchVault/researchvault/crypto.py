"""Versioned, bounded authenticated formats. No GUI or database dependencies."""
import base64
import hashlib
import hmac
import json
import os
import struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

MAX_FILE = 25 * 1024 * 1024
MAX_TEXT = 64 * 1024
MAX_NOTE = 1024 * 1024
MAX_ENVELOPE = MAX_FILE + 8192
PROFILE = 'argon2id-m65536-t3-p4'

class VaultError(Exception):
    """Safe user-facing error; never includes secret input."""


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultError('Data Base64 tidak valid.') from exc


def password_check(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise VaultError('Gunakan passphrase 12–1024 karakter.')


def derive(password, salt):
    password_check(password)
    if len(salt) != 16:
        raise VaultError('Salt tidak valid.')
    return hash_secret_raw(password.encode('utf-8'), salt, 3, 65536, 4, 32, Type.ID)


def seal(data, password, kind):
    if kind not in ('text', 'file', 'file-v2', 'stego', 'master') or len(data) > (MAX_FILE + 4096 if kind == 'file-v2' else MAX_FILE):
        raise VaultError('Jenis atau ukuran payload tidak didukung.')
    salt, nonce = os.urandom(16), os.urandom(12)
    algorithm = 'CHACHA20-POLY1305' if kind in ('file', 'file-v2') else 'AES-256-GCM'
    header = canonical(dict(v=1, kind=kind, alg=algorithm, kdf=PROFILE,
                            salt=b64(salt), nonce=b64(nonce), length=len(data) + 16))
    cipher = ChaCha20Poly1305 if kind in ('file', 'file-v2') else AESGCM
    encrypted = cipher(derive(password, salt)).encrypt(nonce, data, header)
    return b'RVF1' + struct.pack('>I', len(header)) + header + encrypted


def open_envelope(blob, password, kind):
    try:
        if len(blob) > MAX_ENVELOPE or len(blob) < 24 or blob[:4] != b'RVF1':
            raise VaultError('Format envelope tidak valid atau terlalu besar.')
        length = struct.unpack('>I', blob[4:8])[0]
        if not 1 <= length <= 2048 or 8 + length + 16 > len(blob):
            raise VaultError('Header envelope rusak.')
        header = blob[8:8+length]
        info = json.loads(header)
        expected_alg = 'CHACHA20-POLY1305' if kind in ('file', 'file-v2') else 'AES-256-GCM'
        if (not isinstance(info, dict) or info.get('v') != 1 or info.get('kind') != kind or info.get('alg') != expected_alg
                or info.get('kdf') != PROFILE or info.get('length') != len(blob)-8-length):
            raise VaultError('Versi, algoritma, profil KDF, atau panjang tidak didukung.')
        nonce, salt = unb64(info['nonce']), unb64(info['salt'])
        if len(nonce) != 12 or len(salt) != 16:
            raise VaultError('Nonce atau salt tidak valid.')
        cipher = ChaCha20Poly1305 if kind in ('file', 'file-v2') else AESGCM
        return cipher(derive(password, salt)).decrypt(nonce, blob[8+length:], header)
    except InvalidTag as exc:
        raise VaultError('Passphrase salah atau data telah berubah.') from exc
    except (KeyError, ValueError, TypeError, UnicodeError, struct.error) as exc:
        raise VaultError('Envelope tidak dapat dibaca.') from exc


def classic_key(key):
    if not key or len(key) > 1024 or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' for c in key):
        raise VaultError('Kunci Vigenère hanya boleh berisi A–Z, tanpa spasi.')
    return key.upper()


def vigenere(text, key, decrypt=False):
    key, result, index = classic_key(key), [], 0
    for char in text:
        if 'A' <= char <= 'Z' or 'a' <= char <= 'z':
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[index % len(key)]) - 65
            result.append(chr(base + (ord(char)-base + (-shift if decrypt else shift)) % 26))
            index += 1
        else:
            result.append(char)
    return ''.join(result)


def _decrypt_text_v1(text, key, password):
    if not text.startswith('RVTXT1:') or len(text) > MAX_TEXT * 10:
        raise VaultError('Format teks harus RVTXT1: dan berukuran wajar.')
    key = classic_key(key)
    try:
        content = json.loads(open_envelope(unb64(text[7:]), password, 'text'))
        digest = hashlib.sha256(b'RV/vigenere/v1/' + key.encode()).hexdigest()
        if not hmac.compare_digest(content['commitment'], digest):
            raise VaultError('Kunci Vigenère tidak cocok.')
        result = vigenere(content['text'], key, True)
        if len(result.encode()) > MAX_TEXT:
            raise VaultError('Payload teks terlalu besar.')
        return result
    except (ValueError, KeyError, TypeError) as exc:
        raise VaultError('Payload teks rusak.') from exc


# RVTXT2 is a separate, authenticated text format. RVF1 remains unchanged.
TEXT_PIPELINE = ['CAESAR', 'VIGENERE', 'AES-256-GCM', 'CHACHA20-POLY1305']
TEXT_KEYS = 'HKDF-SHA256-RVTXT2'


def caesar_shift_check(shift):
    if type(shift) is not int or not 1 <= shift <= 25:
        raise VaultError('Pergeseran Caesar harus bilangan bulat 1–25.')
    return shift


def caesar(text, shift, decrypt=False):
    caesar_shift_check(shift)
    result = []
    for char in text:
        if 'A' <= char <= 'Z' or 'a' <= char <= 'z':
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr(base + (ord(char)-base + (-shift if decrypt else shift)) % 26))
        else:
            result.append(char)
    return ''.join(result)


def _text_keys(password, salt):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    root = derive(password, salt)
    return tuple(HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                     info=b'ResearchVault/RVTXT2/' + purpose).derive(root)
                 for purpose in (b'AES-256-GCM', b'CHACHA20-POLY1305'))


def _classic_commitment(key, shift):
    return hashlib.sha256(b'ResearchVault/classic/v2/' +
                          canonical(dict(key=classic_key(key), shift=caesar_shift_check(shift)))).hexdigest()


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate field')
        result[key] = value
    return result


def parse_text_v2(value):
    """Bounded structure validation only; authentication happens in decrypt_text."""
    try:
        if not isinstance(value, str) or not value.startswith('RVTXT2:') or len(value) > MAX_TEXT * 10:
            raise ValueError()
        blob = unb64(value[7:])
        if len(blob) < 40 or blob[:4] != b'RVT2':
            raise ValueError()
        length = struct.unpack('>I', blob[4:8])[0]
        if not 1 <= length <= 2048 or len(blob) < 8 + length + 32:
            raise ValueError()
        header, ciphertext = blob[8:8+length], blob[8+length:]
        info = json.loads(header, object_pairs_hook=_strict_object)
        if (not isinstance(info, dict) or set(info) !=
                {'v', 'kind', 'pipeline', 'kdf', 'keys', 'salt', 'aes_nonce', 'chacha_nonce', 'length'}
                or type(info['v']) is not int or info['v'] != 2 or info['kind'] != 'text'
                or info['pipeline'] != TEXT_PIPELINE or info['kdf'] != PROFILE or info['keys'] != TEXT_KEYS
                or type(info['length']) is not int or info['length'] != len(ciphertext)):
            raise ValueError()
        for name, size in [('salt', 16), ('aes_nonce', 12), ('chacha_nonce', 12)]:
            if not isinstance(info[name], str) or len(unb64(info[name])) != size:
                raise ValueError()
        return info, header, ciphertext
    except (ValueError, KeyError, TypeError, UnicodeError, struct.error, RecursionError) as exc:
        raise VaultError('Struktur RVTXT2 rusak atau formatnya tidak didukung.') from exc


def encrypt_text(text, key, password, shift=3):
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_TEXT:
        raise VaultError('Teks maksimal 64 KiB UTF-8.')
    key = classic_key(key)
    caesar_shift_check(shift)
    content = canonical(dict(text=vigenere(caesar(text, shift), key),
                             commitment=_classic_commitment(key, shift)))
    salt, aes_nonce, chacha_nonce = os.urandom(16), os.urandom(12), os.urandom(12)
    header = canonical(dict(v=2, kind='text', pipeline=TEXT_PIPELINE, kdf=PROFILE,
                            keys=TEXT_KEYS, salt=b64(salt), aes_nonce=b64(aes_nonce),
                            chacha_nonce=b64(chacha_nonce), length=len(content)+32))
    aes_key, chacha_key = _text_keys(password, salt)
    inner = AESGCM(aes_key).encrypt(aes_nonce, content, b'RVTXT2/AES/' + header)
    outer = ChaCha20Poly1305(chacha_key).encrypt(chacha_nonce, inner, b'RVTXT2/CHACHA/' + header)
    return 'RVTXT2:' + b64(b'RVT2' + struct.pack('>I', len(header)) + header + outer)


def decrypt_text(text, key, password, shift=3):
    if isinstance(text, str) and text.startswith('RVTXT1:'):
        # The legacy format did not use Caesar or the outer ChaCha layer.
        return _decrypt_text_v1(text, key, password)
    key = classic_key(key)
    caesar_shift_check(shift)
    info, header, ciphertext = parse_text_v2(text)
    aes_key, chacha_key = _text_keys(password, unb64(info['salt']))
    try:
        inner = ChaCha20Poly1305(chacha_key).decrypt(
            unb64(info['chacha_nonce']), ciphertext, b'RVTXT2/CHACHA/' + header)
        plaintext = AESGCM(aes_key).decrypt(unb64(info['aes_nonce']), inner, b'RVTXT2/AES/' + header)
        content = json.loads(plaintext, object_pairs_hook=_strict_object)
        if (not isinstance(content, dict) or set(content) != {'text', 'commitment'}
                or not isinstance(content['text'], str) or not isinstance(content['commitment'], str)):
            raise ValueError()
        if not hmac.compare_digest(content['commitment'], _classic_commitment(key, shift)):
            raise VaultError('Pergeseran Caesar atau kunci Vigenère tidak cocok.')
        result = caesar(vigenere(content['text'], key, True), shift, True)
        if len(result.encode('utf-8')) > MAX_TEXT:
            raise VaultError('Payload teks terlalu besar.')
        return result
    except InvalidTag as exc:
        raise VaultError('Passphrase salah atau data telah berubah.') from exc
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
        raise VaultError('Payload teks rusak.') from exc
