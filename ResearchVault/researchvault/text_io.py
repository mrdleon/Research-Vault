"""Bounded UTF-8 transport for the RVTXT1 and RVTXT2 formats; no keys stored."""
import json
import struct
from .crypto import VaultError, MAX_TEXT, PROFILE, unb64, parse_text_v2

MAX_TEXT_EXPORT = MAX_TEXT * 10


def validate_text_export(value):
    """Check structure only. AEAD authentication is deferred to decryption."""
    if not isinstance(value, str) or len(value) > MAX_TEXT_EXPORT:
        raise VaultError('File teks terenkripsi terlalu besar.')
    value = value.lstrip('\ufeff').strip()
    if value.startswith('RVTXT2:'):
        parse_text_v2(value)
        return value
    if not value.startswith('RVTXT1:'):
        raise VaultError('Pilih hasil Enkripsi teks yang diawali RVTXT1: atau RVTXT2:, bukan teks biasa atau file .rvault.')
    blob = unb64(value[7:])
    try:
        if len(blob) < 24 or blob[:4] != b'RVF1':
            raise ValueError()
        length = struct.unpack('>I', blob[4:8])[0]
        if not 1 <= length <= 2048 or len(blob) < 8 + length + 16:
            raise ValueError()
        header = json.loads(blob[8:8+length])
        if (not isinstance(header, dict) or header.get('v') != 1
                or header.get('kind') != 'text' or header.get('alg') != 'AES-256-GCM'
                or header.get('kdf') != PROFILE or header.get('length') != len(blob)-8-length
                or len(unb64(header['salt'])) != 16 or len(unb64(header['nonce'])) != 12):
            raise ValueError()
    except (ValueError, KeyError, TypeError, UnicodeError, struct.error, RecursionError) as exc:
        raise VaultError('Struktur RVTXT1 rusak atau formatnya tidak didukung.') from exc
    return value
