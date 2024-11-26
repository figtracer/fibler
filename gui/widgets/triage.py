from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame
from PyQt5.QtCore import Qt
from ..styles.default import get_triage_style


class TriageWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_layout()
        self._setup_style_sheet()
        self._setup_labels()

    def _setup_layout(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 20)
        self.layout.setSpacing(0)

        triage_title = QLabel("Triage")
        triage_title.setFixedHeight(45)
        triage_title.setObjectName("triage_title")
        triage_title.setAlignment(Qt.AlignLeft)

        self.labels_container = QFrame()
        self.labels_container.setObjectName("labels_container")
        self.labels_layout = QVBoxLayout(self.labels_container)
        self.labels_layout.setContentsMargins(0, 0, 0, 0)
        self.labels_layout.setSpacing(0)

        self.layout.addWidget(triage_title)
        self.layout.addWidget(self.labels_container)

    def _setup_style_sheet(self):
        self.setStyleSheet(get_triage_style())

    def _setup_labels(self):
        self.labels = {}
        self.add_common_labels()

    def add_common_labels(self):
        default_labels = [
            "File Format",
            "Magic",
            "Architecture",
            "Type",
            "Flags",
            "Text Section Start",
            "Endianness",
            "Total AV Reports",
            "Positive AV Reports",
        ]
        for field in default_labels:
            self.add_label(field)

        self.labels_layout.addStretch()

    # method to populate self.labels with the common labels
    def add_label(self, field_name: str):
        label = QLabel(f"{field_name}: ")
        label.setFixedHeight(29)
        self.labels[field_name] = label
        self.labels_layout.addWidget(label)

    # updates self.labels information
    def update_info(self, field_name: str, value: str):
        if field_name in self.labels:
            text = f'<span style="color: #808080;">{field_name}:</span> <span style="color: #E0E0E0;">{value}</span>'
            self.labels[field_name].setText(text)
        else:
            self.add_label(field_name)
            text = f'<span style="color: #808080;">{field_name}:</span> <span style="color: #E0E0E0;">{value}</span>'
            self.labels[field_name].setText(text)