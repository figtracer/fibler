# ARM64 Disassembler

A disassembler for ARM64 binaries with an intuitive GUI interface built using PyQt5. This tool helps analyze and modify ARM64 executables with features focused on binary analysis and modification.

## Features

✅ **Current Features**
- GUI interface for easy binary navigation
- ARM64 instruction parsing and display
- Mach-O ARM64 format support

🚧 **Upcoming Features**
- VirusTotal API integration for malware analysis
- Virtual address instruction lookup
- Binary modification and rebuilding capabilities
- Instruction modification through context menu
- Comment system for annotations
- Read-only table values with controlled modification through context menu
- and more...

## Requirements

- lief
- capstone
- PyQt5

## Installation

1. Clone the repository
```bash
git clone https://gitlab.com/figtools/disassembler.git
cd disassembler
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

## Usage

Run the main application:
```bash
python main.py
```

## Project Structure

```
├── core/
│   ├── binary_analyzer.py
│   ├── disassembler.py
│   └── parser.py
├── gui/
│   └── main_window.py
└── requirements.txt
```

## Contributing

Feel free to open issues and pull requests for any improvements or bug fixes.