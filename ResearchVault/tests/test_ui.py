import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication
from researchvault.ui import MainWindow, STYLE


def test_ui_shell_and_lock(engine):
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(STYLE)
    window = MainWindow(engine)
    window.show()
    window.root.setCurrentIndex(1)
    window.note_body.setPlainText('unsaved secret')
    window.text_output.setPlainText('plaintext secret')
    app.processEvents()
    assert window.pages.count() == 7
    window.lock_ui('test lock')
    assert window.root.currentIndex() == 0
    assert not window.note_body.toPlainText()
    assert not window.text_output.toPlainText()
    assert engine.user is None
    window.timer.stop()
    window.close()


def test_worker_results_and_navigation(engine):
    import time
    app = QApplication.instance() or QApplication([])
    window = MainWindow(engine)
    window.timer.stop()
    window.root.setCurrentIndex(1)
    received = []
    window.run(lambda: engine.text('Teks uji 🌱','LEMON','Research-password-2026!'),received.append)
    deadline = time.monotonic()+10
    while window.busy and time.monotonic()<deadline:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()
    assert received and received[0].startswith('RVTXT2:')
    assert not window.busy
    window.navigate(3)
    while window.busy and time.monotonic()<deadline:
        app.processEvents()
        time.sleep(0.01)
    assert window.pages.currentIndex() == 3
    window.close()
