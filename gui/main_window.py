from PyQt5.QtWidgets import (
    QApplication,
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
)

from PyQt5.QtGui import QPixmap, QFont, QFontDatabase
from PyQt5.QtCore import Qt
from core.analyzer import Analyzer


class DisassemblerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.binary_info = None

        self._setup_window()
        self._setup_fonts()
        self._setup_style_sheet()
        self._setup_left_side()
        self._setup_file_menu()

    def _setup_fonts(self):
        QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Regular.ttf")
        QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Medium.ttf")
        QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Bold.ttf")

    def _setup_left_side(self):
        self.splitter = QSplitter(Qt.Horizontal)

        # left widget
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # assign the container to the left side layout
        self.table = QTableWidget()
        table_font = QFont("IosevkaTerm Nerd Font", 13)
        self.table.setFont(table_font)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Mnemonic", "Operands"])
        self.table.verticalHeader().setVisible(False)
        self.table.setFrameStyle(0)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        # prevent resizing
        for i in range(0, 3):
            self.table.horizontalHeader().setSectionResizeMode(i, QHeaderView.Fixed)

        # add table to left side of the layout
        left_layout.addWidget(self.table)

        # add left side widget to the splitter
        self.splitter.addWidget(left_widget)

        self.triage_window = TriageWindow()
        self.splitter.addWidget(self.triage_window)

        # set splitter ratio
        self.splitter.setSizes([560, 240])

        # add splitter to main layout
        self.main_layout.addWidget(self.splitter)

    def _setup_window(self):
        self.setWindowTitle("Fibler - ARM64 Disassembler")
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

    def _setup_file_menu(self):
        menu = self.menuBar()
        file_menu = menu.addMenu("File")
        open_action = file_menu.addAction("Open Binary")
        open_action.triggered.connect(self.open_binary)

    def _populate_table(self, instructions: list):
        self.table.setRowCount(len(instructions))
        for row, insn in enumerate(instructions):
            self.table.setItem(row, 0, QTableWidgetItem(f"{insn['address']:08x}"))
            self.table.setItem(row, 1, QTableWidgetItem(insn["mnemonic"]))
            self.table.setItem(row, 2, QTableWidgetItem(insn["op_str"]))

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

        # populate table
        self._populate_table(instructions)

        # update table info
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


# --- RIGHT --->
class TriageWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._setup_image()
        self._setup_layout()
        self._setup_labels()

    def _setup_image(self):
        self.image_label = QLabel()
        pixmap = QPixmap("./gui/images/logo.png")
        scaled_pixmap = pixmap.scaled(
            300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        self.image_label.setPixmap(scaled_pixmap)
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setAttribute(Qt.WA_TranslucentBackground)
        self.image_label.setObjectName("image_label")

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
            
            QLabel#image_label {
                padding: 2px;
                margin-bottom: 10px;
            }
            
            QLabel#triage_title {
                color: #FFFFFF;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 20px;
                font-weight: bold;
                padding: 0px;
                margin: 10px 0px;
            }
            
            QFrame#separator_line {
                background-color: #232323;
                max-height: 1px;
                margin: 0px 0px 15px 0px;
            }
        """
        )

    def _setup_layout(self):
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 20)
        self.layout.setSpacing(0)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setObjectName("separator_line")

        triage_title = QLabel("Triage")
        triage_title.setFixedHeight(45)
        triage_title.setObjectName("triage_title")
        triage_title.setAlignment(Qt.AlignLeft)

        # add widgets to layout
        self.layout.addWidget(self.image_label)
        self.layout.addWidget(triage_title)
        self.layout.addWidget(line)

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

    # populates self.labels with an arbitrary label name
    def add_label(self, field_name: str):
        label = QLabel(f"{field_name}: ")
        label.setFixedHeight(29)
        label.setFont(QFont("IosevkaTerm Nerd Font", 13))
        self.labels[field_name] = label
        self.layout.addWidget(label)

    # updates self.labels information
    def update_info(self, field_name: str, value: str):
        if field_name in self.labels:
            text = f'<span style="color: #808080;">{field_name}:</span> <span style="color: #E0E0E0;">{value}</span>'
            self.labels[field_name].setText(text)
        else:
            self.add_label(field_name)
            text = f'<span style="color: #808080;">{field_name}:</span> <span style="color: #E0E0E0;">{value}</span>'
            self.labels[field_name].setText(text)


# main app
if __name__ == "__main__":
    app = QApplication([])
    gui = DisassemblerGUI()
    gui.show()
    app.exec()
