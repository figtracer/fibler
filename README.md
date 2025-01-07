# Fibler - Advanced ARM64/ARM32 Binary Analysis Tool

Fibler is a binary analysis tool specifically designed for ARM64 and ARM32 architectures. It provides an intuitive graphical interface built with PyQt5, offering powerful features for binary analysis and disassembly. Whether you're a security researcher, reverse engineer, or software developer, Fibler provides the tools you need for comprehensive binary analysis.

## Core Features

Fibler provides comprehensive binary analysis capabilities through an intuitive interface. The tool supports ELF and Mach-O file formats, offering real-time analysis with an advanced disassembly engine powered by Capstone. Users can leverage the integrated VirusTotal scanning for security analysis, utilize the interactive comment system for collaborative work, and navigate through detailed section-based analysis. The import/export table visualization and comprehensive section analysis enhance the understanding of binary structures.

## Prerequisites

Before installing Fibler, ensure your system has:
- Python 3.7 or higher
- C++ compiler with C++17 support

## Installation

1. Clone the Repository:
```bash
git clone https://gitlab.com/figtools/fibler.git
cd fibler
```

2. Create and Activate Virtual Environment:
```bash
python -m venv venv
source venv/bin/activate 
```

3. Install Python Dependencies:
```bash
pip install -r requirements.txt
```

4. Install Native Components:
```bash
pip install -e core/native
```

5. Configure VirusTotal Integration:
```bash
echo "VT_API_KEY=your_virustotal_api_key_here" > .env
```
You can obtain a VirusTotal API key by registering at [VirusTotal.com](https://www.virustotal.com).

## Usage

To start Fibler, run:
```bash
python fibler.py
```

The interface provides several key features for binary analysis:

The Instruction View displays disassembled code with interactive features. Users can add comments by right-clicking on any instruction and selecting "Add Comment" from the context menu. The Triage Panel shows essential binary information, while the Imports/Exports section lists external references. The Sections view provides detailed information about the binary structure.

Quick navigation is available through the "Jump To" menu, which allows jumping between different sections of the binary.

## Project Structure

The project is organized into several key components:

```
├── core/               
│   ├── native/
│   │   ├── include/
│   │   │   ├── elf_parser.hpp
│   │   │   └── elf_types.h
│   │   └── src/
│   │       ├── bindings.cpp
│   │       └── elf_parser.cpp
│   │   └── setup.py    # Native module setup
│   ├── analyzer.py     # Main analysis coordinator
│   ├── disassembler.py # Instruction processing
│   ├── parser.py       # Binary format parsing
│   └── vt.py           # VirusTotal integration
├── gui/
│   ├── fonts/
│   ├── styles/         # UI styling
│   │   └── default.py
│   ├── widgets/        # UI components
│   │   ├── base/       # Base widget implementations
│   │   ├── exports.py
│   │   ├── imports.py
│   │   ├── sections.py
│   │   └── triage.py
│   └── windows/        # Main window implementations
│       ├── main.py
│       └── welcome.py
├── .gitignore
├── fibler.py           # Application entry point
├── README.md
└── requirements.txt
```

## Configuration

Fibler can be configured through environment variables:

- VT_API_KEY: Your VirusTotal API key

## Troubleshooting

If you encounter "ImportError: No module named 'capstone'" or similar dependency errors, reinstall the requirements:
```bash
pip install -r requirements.txt
```

For native module issues, ensure you have the correct C++ compiler installed and try reinstalling the native component:
```bash
pip install -e core/native
```

## License

Fibler is released under the MIT License. See the LICENSE file for details.

## Support

For support create a new issue if needed.

## Acknowledgments

Fibler builds upon several excellent open-source projects:
- Capstone Engine
- PyQt5
- pybind11
- VirusTotal API

Follow [@figtracer](https://twitter.com/figtracer) on Twitter for the latest updates and news.