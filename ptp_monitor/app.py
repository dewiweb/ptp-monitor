"""Point d'entrée de l'application PTP Monitor."""

import sys

from PySide6.QtWidgets import QApplication

from .ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
