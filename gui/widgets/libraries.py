from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QScrollArea
from PyQt5.QtCore import Qt
from ..styles.default import _get_libraries_style


class LibrariesWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_layout()
        self.setStyleSheet(_get_libraries_style())

    def _setup_layout(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 20)
        self.layout.setSpacing(0)

        libraries_title = QLabel("Libraries")
        libraries_title.setFixedHeight(45)
        libraries_title.setObjectName("libraries_title")
        libraries_title.setAlignment(Qt.AlignLeft)

        outer_frame = QFrame()
        outer_frame.setObjectName("libraries_container")
        outer_frame.setFrameShape(QFrame.StyledPanel)
        outer_layout = QVBoxLayout(outer_frame)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.libraries_container = QWidget()
        self.libraries_layout = QVBoxLayout(self.libraries_container)
        self.libraries_layout.setContentsMargins(0, 0, 0, 0)
        self.libraries_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(self.libraries_container)

        outer_layout.addWidget(scroll)

        self.layout.addWidget(libraries_title)
        self.layout.addWidget(outer_frame)

    def add_library_label(self, text: str):
        lib_label = QLabel(text)
        lib_label.setWordWrap(True)
        lib_label.setObjectName("library_item")
        lib_label.setProperty("class", "library_item")
        self.libraries_layout.addWidget(lib_label)

    def _clear_libraries(self):
        while self.libraries_layout.count():
            child = self.libraries_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def update_libraries(self, libraries):
        self._clear_libraries()

        if isinstance(libraries, list):
            # ELF format - libraries is a list of strings
            for lib_name in libraries:
                self.add_library_label(lib_name)
        else:
            # Mach-O format - libraries is an iterator of lief.MachO.DylibCommand
            try:
                for lib in libraries:
                    lib_name = str(lib.name)
                    self.add_library_label(lib_name)
            except AttributeError:
                self.add_library_label("Error: Unable to read library information")

        self.libraries_layout.addStretch()
