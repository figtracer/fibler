from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFontDatabase
from gui.main_window import WelcomeWindow
import sys


def main():
    app = QApplication(sys.argv)
    QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Regular.ttf")
    QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Medium.ttf")
    QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Bold.ttf")
    welcome = WelcomeWindow()
    welcome.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
