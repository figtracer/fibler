from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QFrame,
    QScrollArea,
)
from PyQt5.QtCore import Qt
from ..styles.default import get_exports_style


class ExportsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_layout()
        self._setup_style_sheet()

    def _setup_layout(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 20)
        self.layout.setSpacing(0)

        exports_title = QLabel("Exports")
        exports_title.setFixedHeight(45)
        exports_title.setObjectName("exports_title")
        exports_title.setAlignment(Qt.AlignLeft)

        outer_frame = QFrame()
        outer_frame.setObjectName("exports_container")
        outer_frame.setFrameShape(QFrame.StyledPanel)
        outer_layout = QVBoxLayout(outer_frame)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.exports_container = QWidget()
        self.exports_layout = QVBoxLayout(self.exports_container)
        self.exports_layout.setContentsMargins(0, 0, 0, 0)
        self.exports_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(self.exports_container)

        outer_layout.addWidget(scroll)

        self.layout.addWidget(exports_title)
        self.layout.addWidget(outer_frame)

    def _setup_style_sheet(self):
        self.setStyleSheet(get_exports_style())

    def add_exports_label(self, text: str):
        exports_label = QLabel(text)
        exports_label.setWordWrap(True)
        exports_label.setStyleSheet("color: #E0E0E0;")
        exports_label.setObjectName("exports_item")
        exports_label.setProperty("class", "exports_item")
        self.exports_layout.addWidget(exports_label)

    def _clear_exports(self):
        while self.exports_layout.count():
            child = self.exports_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def update_exports(self, exports):
        self._clear_exports()
        for exported_symbol in exports:
            self.add_exports_label(exported_symbol)
        self.exports_layout.addStretch()
