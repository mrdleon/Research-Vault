import pytest
from PIL import Image
from researchvault import stego
from researchvault.crypto import VaultError

PASSWORD = 'Research-password-2026!'


@pytest.mark.parametrize('mode', ['RGB','RGBA'])
def test_roundtrip_alpha(tmp_path,mode):
    source, output = tmp_path/'source.png',tmp_path/'output.png'
    color = (110,150,200,93) if mode == 'RGBA' else (110,150,200)
    Image.new(mode,(120,120),color).save(source)
    output.write_bytes(stego.embed(source,'Pesan penelitian 🌱',PASSWORD))
    assert stego.extract(output,PASSWORD) == 'Pesan penelitian 🌱'
    if mode == 'RGBA':
        assert Image.open(source).getchannel('A').tobytes() == Image.open(output).getchannel('A').tobytes()
    with pytest.raises(VaultError): stego.extract(output,PASSWORD+'wrong')


def test_too_small(tmp_path):
    p = tmp_path/'tiny.png'
    Image.new('RGB',(2,2)).save(p)
    with pytest.raises(VaultError): stego.embed(p,'hello',PASSWORD)
    with pytest.raises(VaultError): stego.extract(p,PASSWORD)


def test_no_payload_and_wrong_mode(tmp_path):
    p = tmp_path/'blank.png'
    Image.new('RGB',(120,120)).save(p)
    with pytest.raises(VaultError): stego.extract(p,PASSWORD)
    Image.new('L',(120,120)).save(p)
    with pytest.raises(VaultError): stego.embed(p,'hello',PASSWORD)
