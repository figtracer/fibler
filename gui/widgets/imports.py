from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QFrame,
    QScrollArea,
)
from PyQt5.QtCore import Qt
from ..styles.default import get_imports_style


class ImportsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_layout()
        self._setup_style_sheet()

    def _setup_layout(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 20)
        self.layout.setSpacing(0)

        imports_title = QLabel("Imports")
        imports_title.setFixedHeight(45)
        imports_title.setObjectName("imports_title")
        imports_title.setAlignment(Qt.AlignLeft)

        outer_frame = QFrame()
        outer_frame.setObjectName("imports_container")
        outer_frame.setFrameShape(QFrame.StyledPanel)
        outer_layout = QVBoxLayout(outer_frame)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.imports_container = QWidget()
        self.imports_layout = QVBoxLayout(self.imports_container)
        self.imports_layout.setContentsMargins(0, 0, 0, 0)
        self.imports_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(self.imports_container)

        outer_layout.addWidget(scroll)

        self.layout.addWidget(imports_title)
        self.layout.addWidget(outer_frame)

    def _setup_style_sheet(self):
        self.setStyleSheet(get_imports_style())

    def add_imports_label(self, text: str):
        imports_label = QLabel(text)
        imports_label.setWordWrap(True)
        imports_label.setStyleSheet("color: #E0E0E0;")
        imports_label.setObjectName("imports_item")
        imports_label.setProperty("class", "imports_item")
        self.imports_layout.addWidget(imports_label)

    def _clear_imports(self):
        while self.imports_layout.count():
            child = self.imports_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def update_imports(self, imports):
        self._clear_imports()
        for imported_symbol in imports:
            self.add_imports_label(imported_symbol)
        self.imports_layout.addStretch()
