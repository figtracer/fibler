from PyQt5.QtWidgets import QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDesktopWidget, QFileDialog
from ..styles.default import _get_welcome_style
from gui.windows.main import Main


class Welcome(QMainWindow):
    def __init__(self):
        super().__init__()
        self._setup_window()
        self.setStyleSheet(_get_welcome_style())
        self._setup_layout()

    def _setup_window(self):
        self.setWindowTitle("Fibler")
        screen = QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

    def _setup_layout(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)
        layout.setAlignment(Qt.AlignCenter)

        title = QLabel("Fibler")
        title.setAlignment(Qt.AlignCenter)

        subtitle = QLabel("by @figtracer")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(
            """
        QLabel {
            color: #808080;
            font-size: 16px;
            margin-top: -10px;
        }
        """
        )

        self.open_btn = QPushButton("Open Binary")
        self.open_btn.clicked.connect(self.open_binary)
        self.open_btn.setCursor(Qt.PointingHandCursor)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(self.open_btn, alignment=Qt.AlignCenter)

    def open_binary(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Binary", "", "All Files (*)"
        )
        if file_path:
            self.main_window = Main()
            self.main_window.load_binary(file_path)
            self.main_window.showMaximized()
            self.close()
