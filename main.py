from PyQt5.QtWidgets import QApplication
from gui.main_window import DisassemblerGUI
import sys


def main():
    app = QApplication(sys.argv)
    gui = DisassemblerGUI()
    gui.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
