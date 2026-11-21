import os
from pathlib import Path
import sys
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QLockFile
from researchvault.engine import Engine
from researchvault.platform_windows import WindowsPlatform
from researchvault.ui import MainWindow, STYLE


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('ResearchVault')
    app.setStyle('Fusion')
    app.setStyleSheet(STYLE)
    directory = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local' / 'share'))) / 'ResearchVault'
    directory.mkdir(parents=True, exist_ok=True)
    instance_lock = QLockFile(str(directory / 'application.lock'))
    instance_lock.setStaleLockTime(0)
    if not instance_lock.tryLock(0):
        QMessageBox.warning(None, 'ResearchVault', 'ResearchVault sudah berjalan. Buka jendela aplikasi yang sudah aktif.')
        return 1
    try:
        engine = Engine(directory, WindowsPlatform())
        window = MainWindow(engine)
        window.show()
        return app.exec()
    finally:
        instance_lock.unlock()


if __name__ == '__main__':
    sys.exit(main())
