# Fibler - ARM64 Disassembler

A disassembler for ARM64 binaries with an intuitive GUI interface built using PyQt5. This tool helps analyze and modify ARM64 executables with features focused on binary analysis and modification.

## Features

✅ **Current Features**
- GUI interface for easy binary navigation
- ARM64 instruction parsing and display
- Mach-O/ELF ARM64 format support
- VirusTotal API integration (AV reports)

🚧 **Upcoming Features**
- CLI flag (-fe) to search for exports effortlessly
- Virtual address instruction lookup
- Binary modification and rebuilding capabilities
- Instruction modification through context menu
- Comment system for annotations
- Read-only table values with controlled modification through context menu
- and more...

## Installation

1. Clone the repository
```bash
git clone https://gitlab.com/figtools/fibler.git
cd fibler
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

## Usage

1. Create a .env file with: VT_API_KEY=your_api_key_here (500 free lookups per day)

2. Run the main application:
```bash
python fibler.py
```

## Project Structure

```
├── core/
│   ├── binary_analyzer.py
│   ├── disassembler.py
│   ├── parser.py
│   └── vt.py
├── docs/
│   └── images/
│       └── preview.png
├── gui/
│   ├── fonts/
│   │   ├── IosevkaTermNerdFont-Bold
│   │   ├── IosevkaTermNerdFont-Medium
│   │   └── IosevkaTermNerdFont-Regular
│   ├── images/
│   │   └── logo.png
│   └── main_window.py
├── fibler.py
├── README.md
└── requirements.txt
```

## Contributing

Feel free to open issues and pull requests for any improvements or bug fixes.