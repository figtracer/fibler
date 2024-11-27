from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QFrame,
    QScrollArea,
)
from PyQt5.QtCore import Qt
from ...styles.default import _get_base_widget_style


class BaseScrollWidget(QWidget):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.title = title
        self._setup_layout()
        self.setStyleSheet(_get_base_widget_style(self.title.lower()))

    def _setup_layout(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 20)
        self.layout.setSpacing(0)

        title_label = QLabel(self.title)
        title_label.setFixedHeight(45)
        title_label.setObjectName(f"{self.title.lower()}_title")
        title_label.setAlignment(Qt.AlignLeft)

        outer_frame = QFrame()
        outer_frame.setObjectName(f"{self.title.lower()}_container")
        outer_frame.setFrameShape(QFrame.StyledPanel)

        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(self.content_widget)

        outer_layout = QVBoxLayout(outer_frame)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)

        self.layout.addWidget(title_label)
        self.layout.addWidget(outer_frame)

    def _setup_style_sheet(self):
        self.setStyleSheet(self._get_base_style())

    def add_item(self, text: str):
        label = QLabel(text)
        label.setWordWrap(True)
        label.setObjectName(f"{self.title.lower()}_item")
        label.setProperty("class", f"{self.title.lower()}_item")
        self.content_layout.addWidget(label)

    def clear_items(self):
        while self.content_layout.count():
            child = self.content_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def update_items(self, items):
        self.clear_items()
        for item in items:
            self.add_item(item)
        self.content_layout.addStretch()
