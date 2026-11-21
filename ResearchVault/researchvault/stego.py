import io
import struct
from PIL import Image
from .crypto import VaultError, seal, open_envelope, MAX_TEXT
from .storage import read_limited

MAX_PIXELS = 20_000_000


def load_png(path):
    raw = read_limited(path, 100 * 1024 * 1024)
    image = Image.open(io.BytesIO(raw))
    if image.format != 'PNG' or image.mode not in ('RGB', 'RGBA'):
        raise VaultError('Gunakan PNG berwarna RGB atau RGBA.')
    if image.width * image.height > MAX_PIXELS:
        raise VaultError('Gambar maksimal 20 megapiksel.')
    image.load()
    return image


def capacity(path):
    im = load_png(path)
    return im.width, im.height, max(0, im.width * im.height * 3 // 8 - 13)


def embed(path, text, password):
    if len(text.encode()) > MAX_TEXT:
        raise VaultError('Pesan maksimal 64 KiB.')
    image = load_png(path)
    envelope = seal(text.encode(), password, 'stego')
    payload = b'RVST1' + struct.pack('>Q', len(envelope)) + envelope
    if len(payload) * 8 > image.width * image.height * 3:
        raise VaultError('Kapasitas gambar tidak cukup. Pilih gambar yang lebih besar.')
    channels = len(image.getbands())
    data = bytearray(image.tobytes())
    for bit_index in range(len(payload) * 8):
        pos = (bit_index // 3) * channels + bit_index % 3
        bit = (payload[bit_index // 8] >> (7 - bit_index % 8)) & 1
        data[pos] = (data[pos] & 254) | bit
    output = Image.frombytes(image.mode, image.size, bytes(data))
    buffer = io.BytesIO()
    output.save(buffer, format='PNG')
    return buffer.getvalue()


def extract(path, password):
    image = load_png(path)
    channels = len(image.getbands())
    data = image.tobytes()
    cap = image.width * image.height * 3 // 8
    def take(start, count):
        out = bytearray(count)
        for i in range(count * 8):
            bit_index = start * 8 + i
            pos = (bit_index // 3) * channels + bit_index % 3
            out[i // 8] |= (data[pos] & 1) << (7-i % 8)
        return bytes(out)
    if cap < 13:
        raise VaultError('Gambar tidak memuat payload ResearchVault.')
    header = take(0, 13)
    length = struct.unpack('>Q', header[5:])[0]
    if header[:5] != b'RVST1' or not 24 <= length <= min(cap-13, MAX_TEXT+4096):
        raise VaultError('Payload tidak ditemukan atau panjangnya rusak.')
    try:
        return open_envelope(take(13, length), password, 'stego').decode('utf-8')
    except UnicodeError as exc:
        raise VaultError('Pesan bukan UTF-8 valid.') from exc
