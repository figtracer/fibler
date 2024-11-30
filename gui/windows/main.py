from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QMessageBox,
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

from PyQt5.QtCore import Qt, QSignalBlocker
from core.analyzer import Analyzer
from ..widgets.triage import TriageWidget
from ..widgets.libraries import LibrariesWidget
from ..widgets.imports import ImportsWidget
from ..widgets.exports import ExportsWidget
from ..widgets.sections import SectionsWidget


from ..styles.default import _get_main_style


class Main(QMainWindow):
    def __init__(self):
        super().__init__()
        self._setup_window()
        self.setStyleSheet(_get_main_style())
        self._setup_layout()
        self._setup_file_menu()

        self.binary_info = None
        self.instruction_comments = (
            {}
        )

    def closeEvent(self, event):
        self.instruction_comments.clear()
        self.binary_info = None
        super().closeEvent(event)

    def _setup_window(self):
        self.setWindowTitle("Fibler")
        screen = QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

        # main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        self.main_layout = QVBoxLayout(main_widget)

    def _setup_layout(self):
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
        self.sections_widget = SectionsWidget()

        # create a horizontal layout for the exports/imports widgets
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
        right_layout.addWidget(self.sections_widget)

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
        QApplication.setOverrideCursor(Qt.WaitCursor)
        self.table.setUpdatesEnabled(False)

        try:
            self.instruction_comments.clear()
            self.binary_info = None

            analyzer = Analyzer(file_path)
            self.binary_info = analyzer.analyze()
            self._bulk_update_widgets()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load binary: {e}")

        finally:
            self.table.setUpdatesEnabled(True)
            QApplication.restoreOverrideCursor()

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

        # this handles where the context menu will appear
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
            new_text = f"{operands:<30};{comment}"
        else:
            new_text = operands

        operands_item.setText(new_text)

    def populate_table(self, instructions: list):
        self.table.setRowCount(len(instructions))
        self.table.setSortingEnabled(False)

        items = []
        for insn in instructions:
            address = insn["address"]
            address_item = QTableWidgetItem(f"{address:08x}")
            mnemonic_item = QTableWidgetItem(insn["mnemonic"])
            
            operands = insn["op_str"]
            comment = self.instruction_comments.get(address, "")
            operands_text = f"{operands:<30};{comment}" if comment else operands
            operands_item = QTableWidgetItem(operands_text)
            
            items.append((address_item, mnemonic_item, operands_item))

        for row, (addr_item, mnem_item, op_item) in enumerate(items):
            self.table.setItem(row, 0, addr_item)
            self.table.setItem(row, 1, mnem_item)
            self.table.setItem(row, 2, op_item)

        self.table.setSortingEnabled(True)

    def _bulk_update_widgets(self):
        binary_info = self.binary_info["binary_info"]
        
        if binary_info is None:
            raise ValueError("Couldn't get binary information")

        updates = {
            "File Format": binary_info["file_format"],
            "Magic": binary_info["magic"],
            "Architecture": binary_info["architecture"],
            "Type": binary_info["file_type"],
            "Flags": " | ".join(
                str(flag).split(".")[-1] for flag in binary_info["flags"]
            )
            or "none",
            "Text Section Start": hex(binary_info["va"]),
            "Endianness": binary_info["endianness"],
            "Total AV Reports": binary_info["total"],
            "Positive AV Reports": binary_info["positives"],
        }

        with QSignalBlocker(self.triage_widget):
            for key, value in updates.items():
                self.triage_widget.update_info(key, value)

        self.populate_table(self.binary_info["instructions"])

        if "libraries" in binary_info:
            self.libraries_widget.update_items(binary_info["libraries"])
        if "imports" in binary_info:
            self.imports_widget.update_items(binary_info["imports"])
        if "exports" in binary_info:
            self.exports_widget.update_items(binary_info["exports"])
        if "sections" in binary_info:
            self.sections_widget.update_items(binary_info["sections"])
