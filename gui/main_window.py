from PyQt5.QtWidgets import (
    QMainWindow,
    QTableWidget,
    QTableWidgetItem,
    QFileDialog,
    QVBoxLayout,
    QWidget,
    QLabel,
    QSplitter,
    QFrame,
    QHeaderView,
    QDesktopWidget,
    QPushButton,
)

from PyQt5.QtCore import Qt
from core.analyzer import Analyzer


class WelcomeWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._setup_window()
        self._setup_style_sheet()
        self._setup_layout()

    def _setup_window(self):
        self.setWindowTitle("Fibler")
        screen = QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

    def _setup_style_sheet(self):
        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background-color: #191919;
            }
            
            QPushButton {
                background-color: #2C4F6D;
                color: #FFFFFF;
                border: none;
                padding: 10px 20px;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 14px;
                border-radius: 4px;
            }
            
            QPushButton:hover {
                background-color: #3A669D;
            }
            
            QLabel {
                color: #FFFFFF;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 24px;
            }
        """
        )

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


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self._setup_window()
        self._setup_style_sheet()
        self._setup_main_layout()
        self._setup_file_menu()

        self.binary_info = None

    def _setup_window(self):
        self.setWindowTitle("Fibler")
        screen = QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

        # main widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.main_layout = QVBoxLayout(central_widget)

    def _setup_style_sheet(self):
        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #191919;
                color: #E0E0E0;
                font-family: "IosevkaTerm Nerd Font";
            }
            
            QMenuBar {
                background-color: #191919;
                color: #E0E0E0;
                border-bottom: 1px solid #2D2D2D;
                font-family: "IosevkaTerm Nerd Font";
                padding: 2px;
            }
            
            QMenuBar::item:selected {
                background-color: #2D2D2D;
            }
            
            QMenu {
                background-color: #232323;
                color: #E0E0E0;
                border: 1px solid #2D2D2D;
                font-family: "IosevkaTerm Nerd Font";
            }
            
            QMenu::item:selected {
                background-color: #3D3D3D;
            }
            
            QTableWidget {
                background-color: #1E1E1E;
                color: #E0E0E0;
                gridline-color: #2D2D2D;
                border: none;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 13px;
            }
            
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #2D2D2D;
            }
            
            QTableWidget::item:selected {
                background-color: #2C4F6D;
                color: #FFFFFF;
            }
            
            QHeaderView::section {
                background-color: #232323;
                color: #E0E0E0;
                padding: 10px 8px;
                border: none;
                border-right: 1px solid #2D2D2D;
                border-bottom: 2px solid #2D2D2D;
                font-family: "IosevkaTerm Nerd Font";
                font-weight: bold;
            }
            
            QScrollBar:vertical {
                background-color: #1E1E1E;
                width: 14px;
                margin: 0px;
            }
            
            QScrollBar::handle:vertical {
                background-color: #404040;
                min-height: 30px;
                border-radius: 7px;
                margin: 2px;
            }
            
            QScrollBar::handle:vertical:hover {
                background-color: #4D4D4D;
            }
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            
            QSplitter::handle {
                background-color: #2D2D2D;
                width: 2px;
            }
            
            QLabel {
                color: #E0E0E0;
                font-family: "IosevkaTerm Nerd Font";
            }
            
            QFrame[frameShape="4"] {
                background-color: #2D2D2D;
                max-height: 2px;
                margin: 10px 0px; 
            }
        """
        )

    def _setup_main_layout(self):
        self.splitter = QSplitter(Qt.Horizontal)

        # <-------------------------- left side setup
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # setup table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Mnemonic", "Operands"])
        self.table.verticalHeader().setVisible(False)
        self.table.setFrameStyle(0)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        for i in range(0, 3):
            self.table.horizontalHeader().setSectionResizeMode(i, QHeaderView.Fixed)

        # add table to left layout
        left_layout.addWidget(self.table)

        # add the whole left layout+widget to the splitter
        self.splitter.addWidget(left_widget)

        # right side setup ----------------------->
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self.triage_window = TriageWindow()
        self.libraries_window = LibrariesWindow()

        right_layout.addWidget(self.triage_window)
        right_layout.addWidget(self.libraries_window)

        # add the whole right layout+widget to the splitter
        self.splitter.addWidget(right_widget)

        # ------ final settings --------------------------
        self.splitter.setSizes([560, 240])
        self.main_layout.addWidget(self.splitter)

    def _setup_file_menu(self):
        menu = self.menuBar()
        file_menu = menu.addMenu("File")
        open_action = file_menu.addAction("Open Binary")
        open_action.triggered.connect(self.open_binary)

    def open_binary(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Binary", "", "All Files (*)"
        )
        if file_path:
            self.load_binary(file_path)

    def load_binary(self, file_path):
        # analyze the binary
        analyzer = Analyzer(file_path)
        self.binary_info = analyzer.analyze()

        # get instructions
        instructions = self.binary_info["instructions"]

        # populate table and update info
        self.populate_table(instructions)
        self.update_table_info()
        self.update_library_info()

    def populate_table(self, instructions: list):
        self.table.setRowCount(len(instructions))
        for row, insn in enumerate(instructions):
            self.table.setItem(row, 0, QTableWidgetItem(f"{insn['address']:08x}"))
            self.table.setItem(row, 1, QTableWidgetItem(insn["mnemonic"]))
            self.table.setItem(row, 2, QTableWidgetItem(insn["op_str"]))

    def update_table_info(self):
        self.triage_window.update_info(
            "File Format", self.binary_info["binary_info"]["file_format"]
        )

        self.triage_window.update_info(
            "Magic", self.binary_info["binary_info"]["magic"]
        )

        self.triage_window.update_info(
            "Architecture", self.binary_info["binary_info"]["architecture"]
        )

        self.triage_window.update_info(
            "Type", self.binary_info["binary_info"]["file_type"]
        )

        flags = " | ".join(
            str(flag).split(".")[-1]
            for flag in self.binary_info["binary_info"]["flags"]
        )
        if flags:
            self.triage_window.update_info("Flags", flags)
        else:
            self.triage_window.update_info("Flags", "none")

        self.triage_window.update_info(
            "Text Section Start",
            hex(self.binary_info["binary_info"]["text_section_start"]),
        )

        self.triage_window.update_info(
            "Endianness", self.binary_info["binary_info"]["endianness"]
        )

        self.triage_window.update_info(
            "Total AV Reports", self.binary_info["binary_info"]["total"]
        )

        self.triage_window.update_info(
            "Positive AV Reports", self.binary_info["binary_info"]["positives"]
        )

    def update_library_info(self):
        if "libraries" in self.binary_info["binary_info"]:
            self.libraries_window.update_libraries(
                self.binary_info["binary_info"]["libraries"]
            )


class TriageWindow(QWidget):
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

        # add widgets to layout
        self.layout.addWidget(triage_title)
        self.layout.addWidget(self.labels_container)

    def _setup_style_sheet(self):
        self.setStyleSheet(
            """
            QWidget { 
                background-color: #191919;
            }
            
            QLabel {
                color: #E0E0E0;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 13px;
                padding: 4px 0px;
            }
            
            QLabel#triage_title {
                color: #FFFFFF;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 20px;
                font-weight: bold;
                padding: 0px;
                margin: 10px 0px;
            }
            
            QFrame#labels_container {
                background-color: #191919;
                border: 1px solid #2D2D2D;
                border-radius: 4px;
            }
            
            QLabel.info_item {
                color: #E0E0E0;
                background-color: transparent;
                padding: 8px;
                border-bottom: 1px solid #2D2D2D;
            }
            
            QLabel.info_item:last-child {
                border-bottom: none;
            }
        """
        )

    def _setup_labels(self):
        self.labels = {}
        self.add_common_labels()

    # populates self.labels with all the common labels for mach-o and elf
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

    # populates self.labels with an arbitrary label name
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


class LibrariesWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_layout()
        self._setup_style_sheet()

    def _setup_layout(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 20)
        self.layout.setSpacing(0)

        libraries_title = QLabel("Libraries")
        libraries_title.setFixedHeight(45)
        libraries_title.setObjectName("libraries_title")
        libraries_title.setAlignment(Qt.AlignLeft)

        self.libraries_container = QFrame()
        self.libraries_container.setObjectName("libraries_container")
        self.libraries_layout = QVBoxLayout(self.libraries_container)
        self.libraries_layout.setContentsMargins(0, 0, 0, 0)
        self.libraries_layout.setSpacing(0)

        self.layout.addWidget(libraries_title)
        self.layout.addWidget(self.libraries_container)

    def _setup_style_sheet(self):
        self.setStyleSheet(
            """
            QWidget { 
                background-color: #191919;
            }
            
            QLabel {
                color: #E0E0E0;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 13px;
                padding: 4px 0px;
            }
            
            QLabel#libraries_title {
                color: #FFFFFF;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 20px;
                font-weight: bold;
                padding: 0px;
                margin: 10px 0px;
            }
            
            QFrame#libraries_container {
                background-color: #191919;
                border: 1px solid #2D2D2D;
                border-radius: 4px;
            }
            
            QLabel.library_item {
                color: #E0E0E0;
                background-color: transparent;
                padding: 8px;
            }
        """
        )

    def add_library_label(self, text: str):
        lib_label = QLabel(text)
        lib_label.setWordWrap(True)
        lib_label.setStyleSheet("color: #E0E0E0;")
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
