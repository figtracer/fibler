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
)

from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
from core.analyzer import analyze


class DisassemblerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Fibler - ARM64 Disassembler")
        self.setGeometry(100, 100, 1200, 800)

        # to store binary info, preventing another parse
        self.binary_info = None

        # main widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # layout
        layout = QVBoxLayout(central_widget)

        # create splitter
        splitter = QSplitter(Qt.Horizontal)

        # <--- LEFT SIDE ---
        # create widget (container) for the left side of the splitter + layout
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        # assign the container to the left side layout
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Mnemonic", "Operands"])
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
        self.table.resizeColumnsToContents()

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
        pixmap = QPixmap("./images/logo.png")

        scaled_pixmap = pixmap.scaled(
            300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )

        image_label.setPixmap(scaled_pixmap)
        image_label.setAlignment(Qt.AlignCenter)

        # layout settings
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)

        # set style sheet for the all labels
        self.setStyleSheet(
            """
            QLabel {
                margin-bottom: 10px;
                font-size: 14px;
            }
            QLabel#image_label {
                padding: 2px;
                font-size:20px;
                margin: 0px;
            }
            QLabel#triage_title {
                font-size:17px;
                font-weight:bold;
            }
        """
        )

        image_label.setObjectName("image_label")

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)

        triage_title = QLabel("Triage")
        triage_title.setFixedHeight(30)
        triage_title.setObjectName("triage_title")

        # add title to layout
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
        label.setFixedHeight(30)
        self.labels[field_name] = label
        self.layout.addWidget(label)

    """ updates self.labels information """

    def update_info(self, field_name: str, value: str):
        if field_name in self.labels:
            self.labels[field_name].setText(f"{field_name}: {value}")
        else:
            self.add_label(field_name)
            self.labels[field_name].setText(f"{field_name}: {value}")


# TODO: class TriageWindow QWidget


# main app
if __name__ == "__main__":
    app = QApplication([])
    gui = DisassemblerGUI()
    gui.show()
    app.exec()
