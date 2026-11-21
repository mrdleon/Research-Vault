import json
import struct
import pytest
from researchvault.crypto import *
from researchvault.storage import atomic_new, read_limited

PASSWORD = 'Research-password-2026!'


def test_vigenere_vector():
    assert vigenere('Attack at dawn!', 'LEMON') == 'Lxfopv ef rnhr!'
    assert vigenere('Lxfopv ef rnhr!', 'lemon', True) == 'Attack at dawn!'


@pytest.mark.parametrize('message', ['', 'Penelitian 🌱 αβé\n2026!', 'aZ' * 1000])
def test_text_roundtrip(message):
    result = encrypt_text(message, 'LEMON', PASSWORD)
    assert decrypt_text(result, 'lemon', PASSWORD) == message


def test_randomness():
    assert encrypt_text('hello', 'KEY', PASSWORD) != encrypt_text('hello', 'KEY', PASSWORD)


@pytest.mark.parametrize('key,password', [('WRONG', PASSWORD), ('LEMON', PASSWORD+'x')])
def test_wrong_keys(key, password):
    blob = encrypt_text('secret', 'LEMON', PASSWORD)
    with pytest.raises(VaultError): decrypt_text(blob, key, password)


@pytest.mark.parametrize('kind', ['file', 'text', 'stego', 'master'])
def test_aead_tamper(kind):
    blob = seal(b'secret\x00\xff', PASSWORD, kind)
    assert open_envelope(blob, PASSWORD, kind) == b'secret\x00\xff'
    with pytest.raises(VaultError): open_envelope(blob[:-1] + bytes([blob[-1]^1]), PASSWORD, kind)
    with pytest.raises(VaultError): open_envelope(blob[:-10], PASSWORD, kind)


def test_kdf_allowlist():
    blob = seal(b'test', PASSWORD, 'file')
    n = struct.unpack('>I', blob[4:8])[0]
    header = json.loads(blob[8:8+n])
    header['kdf'] = 'argon2id-m999999999999-t9999'
    changed = canonical(header)
    with pytest.raises(VaultError):
        open_envelope(b'RVF1'+struct.pack('>I',len(changed))+changed+blob[8+n:], PASSWORD, 'file')


@pytest.mark.parametrize('blob', [b'', b'RVF1', b'RVF1'+b'\xff'*30, b'not an envelope'])
def test_malformed(blob):
    with pytest.raises(VaultError): open_envelope(blob, PASSWORD, 'file')


def test_domain_separation():
    with pytest.raises(VaultError): open_envelope(seal(b'test', PASSWORD, 'stego'), PASSWORD, 'text')


def test_invalid_classic():
    for key in ('', 'A1', 'é', 'ABC DEF'):
        with pytest.raises(VaultError): vigenere('hello', key)


def test_output_no_overwrite(tmp_path):
    p = tmp_path/'output'
    p.write_bytes(b'original')
    with pytest.raises(VaultError): atomic_new(p,b'changed')
    assert p.read_bytes() == b'original'


def test_cancelled_output(tmp_path):
    p = tmp_path/'output'
    def cancelled(): raise VaultError('locked')
    with pytest.raises(VaultError): atomic_new(p,b'secret',cancelled)
    assert not p.exists()
    assert not list(tmp_path.glob('.rv-*'))


def test_file_size_boundary(tmp_path):
    p = tmp_path/'file'
    p.write_bytes(b'x'*100)
    assert len(read_limited(p,100)) == 100
    with pytest.raises(VaultError): read_limited(p,99)
