"""Real Windows adapters. Unsupported systems fail closed; no production mock mode."""
import ctypes
import hashlib
import os
from pathlib import Path
import sys
from .crypto import VaultError, canonical


def require_windows():
    if sys.platform != 'win32':
        raise VaultError('Login membutuhkan Windows 11, Windows Hello, dan USB terdaftar.')


class WindowsPlatform:
    def sid(self):
        require_windows()
        import win32api, win32security, win32con
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            return win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        finally:
            token.Close()

    def protect(self, data):
        require_windows()
        import win32crypt
        return win32crypt.CryptProtectData(data, 'ResearchVault/v1', None, None, None, 1)

    def unprotect(self, data):
        require_windows()
        import win32crypt
        try:
            return win32crypt.CryptUnprotectData(data, None, None, None, 1)[1]
        except Exception as exc:
            raise VaultError('Key store tidak dapat dibuka oleh akun Windows ini.') from exc

    def hello(self, hwnd):
        require_windows()
        root = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent.parent))
        path = root / 'native' / 'researchvault_hello.dll'
        if not path.exists():
            raise VaultError('Adapter Hello belum dibangun. Jalankan BUILD_HELLO.bat; baca README.')
        dll = ctypes.CDLL(str(path))
        function = dll.verify_hello
        function.argtypes, function.restype = [ctypes.c_void_p], ctypes.c_int
        if function(hwnd) != 0:
            raise VaultError('Verifikasi Windows Hello dibatalkan, gagal, atau tidak tersedia.')

    def devices(self):
        require_windows()
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        try:
            service = win32com.client.GetObject('winmgmts:root\\cimv2')
            result = []
            disks = service.ExecQuery('SELECT * FROM Win32_DiskDrive')
            for disk in disks:
                pnp = str(disk.PNPDeviceID or '')
                if str(disk.InterfaceType) != 'USB' and not pnp.upper().startswith('USBSTOR'):
                    continue
                serial = str(disk.SerialNumber or '').strip()
                if not serial or not pnp:
                    continue
                for partition in disk.Associators_('Win32_DiskDriveToDiskPartition'):
                    for volume in partition.Associators_('Win32_LogicalDiskToPartition'):
                        drive = str(volume.DeviceID) + '\\'
                        volume_serial = str(volume.VolumeSerialNumber or '')
                        if not volume_serial:
                            continue
                        identity = hashlib.sha256(canonical(dict(serial=serial, pnp=pnp, volume=volume_serial))).hexdigest()
                        result.append(dict(root=drive, fingerprint=identity,
                                           label=f'{drive} {str(volume.VolumeName or "USB")} · {serial[-6:]}'))
            # Ambiguous identities are refused, rather than choosing the first.
            return [d for d in result if sum(x['fingerprint'] == d['fingerprint'] for x in result) == 1]
        finally:
            pythoncom.CoUninitialize()
