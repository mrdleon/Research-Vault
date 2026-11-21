from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from researchvault.engine import Engine
from researchvault.crypto import VaultError

PASSWORD = 'Research-password-2026!'


class TestPlatform:
    """Test double ONLY; never imported by the application."""
    __test__ = False
    def __init__(self, directory):
        self.identity = 'TEST-SID'
        self.allow_hello = True
        self.connected = True
        directory.mkdir()
        self.device = dict(root=str(directory), fingerprint='TEST-USB-1', label='Test USB')
    def sid(self): return self.identity
    def protect(self, value): return b'TEST_ONLY:' + value
    def unprotect(self, value):
        if not value.startswith(b'TEST_ONLY:'):
            raise VaultError('Invalid test key store')
        return value[10:]
    def devices(self): return [self.device] if self.connected else []
    def hello(self, hwnd):
        if not self.allow_hello:
            raise VaultError('Hello cancelled')


@pytest.fixture
def platform(tmp_path):
    return TestPlatform(tmp_path / 'usb')


@pytest.fixture
def engine(tmp_path, platform):
    e = Engine(tmp_path / 'vault', platform)
    e.register('marvel', 'Marvel', PASSWORD, platform.device['fingerprint'], 1)
    e.login('marvel', PASSWORD, 1)
    return e
