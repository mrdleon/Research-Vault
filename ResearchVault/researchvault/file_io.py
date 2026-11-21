"""Encrypted file metadata and safe recovery naming; no format guessing."""
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
from .crypto import VaultError, MAX_FILE, MAX_ENVELOPE, canonical, open_envelope


def safe_name(name):
    if (not isinstance(name, str) or not name or len(name.encode('utf-8')) > 1024
            or name in ('.', '..') or name[-1:] in (' ', '.')
            or any(ord(c) < 32 or c in '<>:"/\\|?*' for c in name)
            or name.split('.')[0].upper() in {'CON','PRN','AUX','NUL',
                *('COM'+str(i) for i in range(1,10)), *('LPT'+str(i) for i in range(1,10))}):
        raise VaultError('Nama file asli tidak aman atau tidak didukung pada Windows.')
    return name


def pack_file(raw, name):
    name = safe_name(name)
    if len(raw) > MAX_FILE:
        raise VaultError('File maksimal 25 MiB.')
    metadata = canonical(dict(name=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    if len(metadata) > 2048:
        raise VaultError('Metadata file terlalu besar.')
    return b'RVP2' + struct.pack('>I', len(metadata)) + metadata + raw


def unpack_file(raw):
    try:
        if raw[:4] != b'RVP2' or len(raw) < 8:
            raise ValueError()
        n = struct.unpack('>I', raw[4:8])[0]
        if not 1 <= n <= 2048 or len(raw) < 8+n:
            raise ValueError()
        metadata = json.loads(raw[8:8+n])
        data = raw[8+n:]
        if (not isinstance(metadata, dict) or set(metadata) != {'name','size','sha256'}
                or type(metadata['size']) is not int or metadata['size'] != len(data)
                or len(data) > MAX_FILE or not isinstance(metadata['sha256'], str)
                or not re.fullmatch('[0-9a-f]{64}', metadata['sha256'])):
            raise ValueError()
        name = safe_name(metadata['name'])
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), metadata['sha256']):
            raise VaultError('Isi file tidak cocok dengan sidik jari asli. Tidak ada hasil yang disimpan.')
        return data, name
    except (ValueError, TypeError, KeyError, UnicodeError, struct.error, RecursionError) as exc:
        raise VaultError('Metadata file terenkripsi rusak atau tidak didukung.') from exc


def decrypt_file(blob, password):
    try:
        if not 24 <= len(blob) <= MAX_ENVELOPE or blob[:4] != b'RVF1':
            raise ValueError()
        n = struct.unpack('>I', blob[4:8])[0]
        if not 1 <= n <= 2048 or len(blob) < 8+n+16:
            raise ValueError()
        info = json.loads(blob[8:8+n])
        if not isinstance(info, dict) or info.get('kind') not in ('file','file-v2'):
            raise ValueError()
        kind = info['kind']
    except (ValueError, TypeError, KeyError, UnicodeError, struct.error, RecursionError) as exc:
        raise VaultError('Pilih file .rvault hasil enkripsi file ResearchVault yang valid.') from exc
    raw = open_envelope(blob, password, kind)
    if kind == 'file-v2':
        return unpack_file(raw)
    if len(raw) > MAX_FILE:
        raise VaultError('File maksimal 25 MiB.')
    return raw, None


def recovery_target(target, source, original_name=None, legacy_extension=''):
    """Directory mode restores name; explicit-file mode never overwrites."""
    target, source = Path(target), Path(source)
    if target.is_dir():
        if original_name:
            name = original_name
        else:
            # v1 had no filename metadata. A preserved name is only a hint,
            # never proof of the original type; otherwise ask the user.
            name = source.name[:-7] if source.name.lower().endswith('.rvault') else source.name
            if legacy_extension:
                if not re.fullmatch(r'\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*', legacy_extension):
                    raise VaultError('Ekstensi file lama harus seperti .pdf, .docx, atau .tar.gz.')
                if not name.lower().endswith(legacy_extension.lower()):
                    name = Path(name).stem + legacy_extension
            elif not Path(name).suffix:
                raise VaultError('File lama tidak menyimpan nama/ekstensi asli. Isi Ekstensi file lama, misalnya .pdf atau .docx, sesuai file sumber dahulu.')
        name = safe_name(name)
        candidate = target / name
        suffix = ''.join(Path(name).suffixes)
        stem = name[:-len(suffix)] if suffix else name
        for i in range(10000):
            if not candidate.exists():
                return candidate
            candidate = target / (stem + f' (dipulihkan {i+1})' + suffix)
        raise VaultError('Terlalu banyak hasil dengan nama sama. Pilih folder lain.')
    if original_name:
        suffix = Path(original_name).suffix
        for compound in ('.tar.gz', '.tar.bz2', '.tar.xz'):
            if original_name.lower().endswith(compound):
                suffix = original_name[-len(compound):]
                break
        if suffix and not target.suffix:
            target = target.with_name(target.name + suffix)
        elif suffix and not target.name.lower().endswith(suffix.lower()):
            raise VaultError(f'Ekstensi hasil harus {suffix}. Pilih folder tujuan untuk memulihkan nama asli otomatis.')
    return target
