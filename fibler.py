from PyQt5.QtWidgets import QApplication
from gui.windows.welcome import Welcome
import sys


def main():
    app = QApplication(sys.argv)
    welcome = Welcome()
    welcome.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
