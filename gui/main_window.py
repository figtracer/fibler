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
from core.analyzer import analyze


class DisassemblerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Fibler - ARM64 Disassembler")

        screen = QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

        # to store binary info, preventing another parse
        self.binary_info = None

        # main widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # layout
        layout = QVBoxLayout(central_widget)

        # add fonts to use in layout
        QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Regular.ttf")
        QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Medium.ttf")
        QFontDatabase.addApplicationFont("./fonts/IosevkaTermNerdFont-Bold.ttf")

        # set theme
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

        # create splitter
        splitter = QSplitter(Qt.Horizontal)

        # <--- LEFT SIDE ---
        # create widget (container) for the left side of the splitter + layout
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

        # prevent resizing
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)

        # prevent direct editing
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        # add table to left side of the layout
        left_layout.addWidget(self.table)

        # add left side widget to the splitter
        splitter.addWidget(left_widget)

        # --- RIGHT SIZE --->
        # create triage window and add it to the splitter (right size)
        self.triage_window = TriageWindow()
        splitter.addWidget(self.triage_window)

        # set ratio
        splitter.setSizes([560, 240])

        # add splitter container to main layout
        layout.addWidget(splitter)

        # file menu for loading binaries
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
        self.binary_info = analyze(file_path)
        instructions = self.binary_info["instructions"]

        # populate table with instructions
        self.table.setRowCount(len(instructions))
        for row, insn in enumerate(instructions):
            self.table.setItem(row, 0, QTableWidgetItem(f"{insn['address']:08x}"))
            self.table.setItem(row, 1, QTableWidgetItem(insn["mnemonic"]))
            self.table.setItem(row, 2, QTableWidgetItem(insn["op_str"]))

        # update file format value
        self.triage_window.update_info(
            "File Format", self.binary_info["binary_info"]["file_format"]
        )

        # update magic value
        self.triage_window.update_info(
            "Magic", self.binary_info["binary_info"]["magic"]
        )

        # update architecture value
        self.triage_window.update_info(
            "Architecture", self.binary_info["binary_info"]["architecture"]
        )

        # update file type value
        self.triage_window.update_info(
            "Type", self.binary_info["binary_info"]["file_type"]
        )

        # update flags info
        flags = " | ".join(
            str(flag).split(".")[-1]
            for flag in self.binary_info["binary_info"]["flags"]
        )

        if flags:
            self.triage_window.update_info("Flags", flags)
        else:
            self.triage_window.update_info("Flags", "none")

        # update text section start address value
        self.triage_window.update_info(
            "Text Section Start",
            hex(self.binary_info["binary_info"]["text_section_start"]),
        )

        # update endianness value
        self.triage_window.update_info(
            "Endianness", self.binary_info["binary_info"]["endianness"]
        )


# --- RIGHT --->
class TriageWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        image_label = QLabel()
        pixmap = QPixmap("./gui/images/logo.png")
        scaled_pixmap = pixmap.scaled(
            300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        image_label.setPixmap(scaled_pixmap)
        image_label.setAlignment(Qt.AlignCenter)
        image_label.setAttribute(Qt.WA_TranslucentBackground)
        image_label.setObjectName("image_label")

        # layout settings
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 0, 20, 20)
        self.layout.setSpacing(0)

        # set style sheet for the all labels
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

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setObjectName("separator_line")

        triage_title = QLabel("Triage")
        triage_title.setFixedHeight(45)
        triage_title.setObjectName("triage_title")
        triage_title.setAlignment(Qt.AlignLeft)

        # add widgets to layout
        self.layout.addWidget(image_label)
        self.layout.addWidget(triage_title)
        self.layout.addWidget(line)

        # labels
        self.labels = {}
        self.add_common_labels()

    """ populates self.labels with all the common labels for mach-o and elf """

    def add_common_labels(self):
        default_labels = [
            "File Format",
            "Magic",
            "Architecture",
            "Type",
            "Flags",
            "Text Section Start",
            "Endianness",
        ]
        for field in default_labels:
            self.add_label(field)

    """ populates self.labels with an arbitrary label name """

    def add_label(self, field_name: str):
        label = QLabel(f"{field_name}: ")
        label.setFixedHeight(29)
        label.setFont(QFont("IosevkaTerm Nerd Font", 13))
        self.labels[field_name] = label
        self.layout.addWidget(label)

    """ updates self.labels information """

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
