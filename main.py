from PyQt5.QtWidgets import QApplication
from gui.main_window import DisassemblerGUI  # Import your main GUI class

def main():
    import sys  # Required for the application loop
    app = QApplication(sys.argv)  # Initialize the PyQt application
    gui = DisassemblerGUI()       # Create an instance of the main window
    gui.show()                    # Show the main window
    sys.exit(app.exec())          # Start the application event loop

if __name__ == "__main__":
    main()