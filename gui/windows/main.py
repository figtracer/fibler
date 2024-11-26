from PyQt5.QtWidgets import (
    QMainWindow,
    QTableWidget,
    QTableWidgetItem,
    QFileDialog,
    QVBoxLayout,
    QWidget,
    QSplitter,
    QHeaderView,
    QDesktopWidget,
    QHBoxLayout,
    QMenu,
    QInputDialog,
    QAction,
)

from PyQt5.QtCore import Qt
from core.analyzer import Analyzer
from ..widgets.triage import TriageWidget
from ..widgets.libraries import LibrariesWidget
from ..widgets.imports import ImportsWidget
from ..widgets.exports import ExportsWidget


from ..styles.default import get_main_style


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self._setup_window()
        self._setup_style_sheet()
        self._setup_main_layout()
        self._setup_file_menu()

        self.binary_info = None
        self.instruction_comments = (
            {}
        )  # dictionary to store comments for each instruction

    def _setup_window(self):
        self.setWindowTitle("Fibler")
        screen = QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

        # main widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.main_layout = QVBoxLayout(central_widget)

    def _setup_style_sheet(self):
        self.setStyleSheet(get_main_style())

    def _setup_main_layout(self):
        self.splitter = QSplitter(Qt.Horizontal)

        # <-------------------------- left side setup
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Address", "Mnemonic", "Operands"])
        self.table.verticalHeader().setVisible(False)
        self.table.setFrameStyle(0)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

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

        self.triage_widget = TriageWidget()
        self.libraries_widget = LibrariesWidget()
        self.imports_widget = ImportsWidget()
        self.exports_widget = ExportsWidget()

        imports_exports_widget = QWidget()
        imports_exports_layout = QHBoxLayout(imports_exports_widget)
        imports_exports_layout.setContentsMargins(0, 0, 0, 0)
        imports_exports_layout.setSpacing(0)

        imports_exports_layout.addWidget(self.imports_widget)
        imports_exports_layout.addWidget(self.exports_widget)

        right_layout.addWidget(self.triage_widget)
        right_layout.addWidget(self.libraries_widget)
        right_layout.addWidget(imports_exports_widget)

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
        self.update_imports_info()
        self.update_exports_info()

    def show_context_menu(self, position):
        item = self.table.itemAt(position)
        if not item:
            return

        context_menu = QMenu()
        row = self.table.row(item)

        address_item = self.table.item(row, 0)
        if not address_item:
            return

        address = int(address_item.text(), 16)

        add_comment_action = QAction("Add/Edit Comment", self)
        delete_comment_action = QAction("Delete Comment", self)

        context_menu.addAction(add_comment_action)
        context_menu.addAction(delete_comment_action)

        add_comment_action.triggered.connect(lambda: self.add_comment(address, row))
        delete_comment_action.triggered.connect(
            lambda: self.delete_comment(address, row)
        )

        # handles where the context menu will appear
        context_menu.exec_(self.table.viewport().mapToGlobal(position))

    # adds comment to self.instruction_comments
    def add_comment(self, address, row):
        comment, ok = QInputDialog.getText(
            self,
            "Add Comment",
            "Enter comment for instruction:",
            text=self.instruction_comments.get(address, ""),
        )

        if ok:
            if comment:
                self.instruction_comments[address] = comment
            elif address in self.instruction_comments:
                del self.instruction_comments[address]
            self.update_comment_in_table(row, address)

    def delete_comment(self, address, row):
        if address in self.instruction_comments:
            del self.instruction_comments[address]
            self.update_comment_in_table(row, address)

    # sends update to self.table
    def update_comment_in_table(self, row, address):
        operands_item = self.table.item(row, 2)
        if not operands_item:
            return

        # prevent multiple comments from being added on the same line
        operands = operands_item.text().split(";")[0].strip()
        comment = self.instruction_comments.get(address, "")

        # format the operands with comment
        if comment:
            new_text = f"{operands}    ; {comment}"
        else:
            new_text = operands

        operands_item.setText(new_text)

    def populate_table(self, instructions: list):
        self.table.setRowCount(len(instructions))
        for row, insn in enumerate(instructions):
            address = insn["address"]
            self.table.setItem(row, 0, QTableWidgetItem(f"{insn['address']:08x}"))
            self.table.setItem(row, 1, QTableWidgetItem(insn["mnemonic"]))

            operands = insn["op_str"]
            comment = self.instruction_comments.get(address, "")
            if comment:
                operands_text = f"{operands}    ; {comment}"
            else:
                operands_text = operands

            self.table.setItem(row, 2, QTableWidgetItem(operands_text))

    def update_table_info(self):
        self.triage_widget.update_info(
            "File Format", self.binary_info["binary_info"]["file_format"]
        )

        self.triage_widget.update_info(
            "Magic", self.binary_info["binary_info"]["magic"]
        )

        self.triage_widget.update_info(
            "Architecture", self.binary_info["binary_info"]["architecture"]
        )

        self.triage_widget.update_info(
            "Type", self.binary_info["binary_info"]["file_type"]
        )

        flags = " | ".join(
            str(flag).split(".")[-1]
            for flag in self.binary_info["binary_info"]["flags"]
        )
        if flags:
            self.triage_widget.update_info("Flags", flags)
        else:
            self.triage_widget.update_info("Flags", "none")

        self.triage_widget.update_info(
            "Text Section Start",
            hex(self.binary_info["binary_info"]["text_section_start"]),
        )

        self.triage_widget.update_info(
            "Endianness", self.binary_info["binary_info"]["endianness"]
        )

        self.triage_widget.update_info(
            "Total AV Reports", self.binary_info["binary_info"]["total"]
        )

        self.triage_widget.update_info(
            "Positive AV Reports", self.binary_info["binary_info"]["positives"]
        )

    def update_library_info(self):
        if "libraries" in self.binary_info["binary_info"]:
            self.libraries_widget.update_libraries(
                self.binary_info["binary_info"]["libraries"]
            )

    def update_imports_info(self):
        if "imports" in self.binary_info["binary_info"]:
            self.imports_widget.update_imports(
                self.binary_info["binary_info"]["imports"]
            )

    def update_exports_info(self):
        if "exports" in self.binary_info["binary_info"]:
            self.exports_widget.update_exports(
                self.binary_info["binary_info"]["exports"]
            )
