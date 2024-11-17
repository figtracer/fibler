from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QTableWidget,
    QTableWidgetItem,
    QFileDialog,
    QVBoxLayout,
    QWidget,
)

from core.analyzer import analyze


class DisassemblerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ARM64 Disassembler")
        self.setGeometry(100, 100, 800, 600)

        # to store binary info
        self.binary_info = None
        self.triage_window = None

        # main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # table to display instructions
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Mnemonic", "Operands"])
        self.layout.addWidget(self.table)

        # file menu for loading binaries
        self.menu = self.menuBar()
        self.file_menu = self.menu.addMenu("File")

        open_action = self.file_menu.addAction("Open Binary")
        open_action.triggered.connect(self.open_binary)

    def open_binary(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Binary", "", "All Files (*)"
        )
        if file_path:
            self.load_binary(file_path)

    def load_binary(self, file_path):
        # analyze the binary
        analysis = analyze(file_path)
        instructions = analysis["instructions"]

        # populate table with instructions
        self.table.setRowCount(len(instructions))
        for row, insn in enumerate(instructions):
            self.table.setItem(row, 0, QTableWidgetItem(f"{insn['address']:016x}"))
            self.table.setItem(row, 1, QTableWidgetItem(insn["mnemonic"]))
            self.table.setItem(row, 2, QTableWidgetItem(insn["op_str"]))
        self.table.resizeColumnsToContents()


# TODO: class TriageWindow QWidget


# main app
if __name__ == "__main__":
    app = QApplication([])
    gui = DisassemblerGUI()
    gui.show()
    app.exec()
