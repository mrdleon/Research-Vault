import ctypes
import hashlib
import os
from pathlib import Path
import tempfile
from .crypto import VaultError, MAX_FILE


def read_limited(path, maximum=MAX_FILE):
    with open(path, 'rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise VaultError('Ukuran file melebihi batas operasi.')
    return data


def atomic_new(path, data, guard=lambda: None):
    """Atomic no-replace publication (hard link); never clobber an existing output."""
    path = Path(path)
    if path.exists():
        raise VaultError('Tujuan sudah ada. Pilih nama file baru.')
    fd, temporary = tempfile.mkstemp(prefix='.rv-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        guard()
        # os.link fails if a target is concurrently created; unlike os.replace.
        if os.name == 'nt':
            move = ctypes.WinDLL('kernel32', use_last_error=True).MoveFileExW
            move.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
            move.restype = ctypes.c_int
            if not move(str(temporary), str(path), 0x8):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _hash_open_file(stream):
    before = os.fstat(stream.fileno())
    digest = hashlib.sha256()
    count = 0
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
        count += len(chunk)
    after = os.fstat(stream.fileno())
    if _file_signature(before) != _file_signature(after) or count != after.st_size:
        raise VaultError('File berubah saat hashing. Tutup aplikasi yang menyimpan file lalu coba lagi.')
    return digest.digest(), after


def _file_signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_hash(path):
    """Hash a stable file, comparing metadata from the SAME API on all reads.

    Do not compare os.fstat() to os.stat(): Windows/Python versions can
    represent file identity or timestamps differently across these APIs.
    Reopening also checks that the path still resolves to the same file.
    A second digest detects changed bytes even when metadata is unchanged.
    This is a consistency check, not an OS snapshot or protection against
    a hostile writer that controls the file throughout both reads.
    """
    with open(path, 'rb') as stream:
        first_digest, first_info = _hash_open_file(stream)
    with open(path, 'rb') as stream:
        second_digest, second_info = _hash_open_file(stream)
    if (_file_signature(first_info) != _file_signature(second_info)
            or first_digest != second_digest):
        raise VaultError('File berubah saat hashing. Tutup aplikasi yang menyimpan file lalu coba lagi.')
    return first_digest.hex()
