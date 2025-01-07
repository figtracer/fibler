def _get_welcome_style():
    return """
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


def _get_main_style():
    return """
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
                background-color: #400000;
                color: #FFFFFF;
            }
            
            QTableWidget::item[section="true"] {
                padding: 10px;
                text-align: center;
                font-weight: bold;
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


def _get_triage_style():
    return """
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


def _get_base_widget_style(title):
    return f"""
        QWidget {{
        background-color: #191919;
            }}
        
            QLabel {{
                color: #E0E0E0;
                font-family: "IosevkaTerm Nerd Font";
                font-size: 13px;
                padding: 4px 0px;
            }}

            QLabel#{title}_title {{
                color: #FFFFFF;
                font-size: 20px;
                font-weight: bold;
                padding: 0px;
                margin: 10px 0px;
            }}
        
            QFrame#{title}_container {{
                background-color: #191919;
                border: 1px solid #2D2D2D;
                border-radius: 4px;
            }}
        
            QScrollArea {{
                border: none;
                background-color: transparent;
            }}
        
            QScrollBar:vertical {{
                border: none;
                background: #1e1e1e;
                width: 10px;
            }}
        
            QScrollBar::handle:vertical {{
                background: #404040;
                min-height: 20px;
                border-radius: 5px;
            }}
        """
