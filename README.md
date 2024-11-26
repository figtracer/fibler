# Fibler - ARM64 Disassembler

A disassembler for ARM64 binaries with an intuitive GUI interface built using PyQt5. This tool helps analyze and modify ARM64 executables with features focused on binary analysis and modification.

## Features

✅ **Current Features**
- GUI interface for easy binary navigation
- Mach-O/ELF ARM64 format support
- VirusTotal API integration (AV reports)
- Comment system for annotations

🚧 **Upcoming Features**
- CLI flag (-fe) to search for exports effortlessly
- Virtual address instruction lookup
- Binary modification and rebuilding capabilities
- Instruction modification through context menu
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
1. Create an account on VirusTotal and get your API Key (free 500 lookups/day).

2. Create a .env file inside the project directory with your API Key: ```echo "VT_API_KEY=your_api_key_here" > .env```
    > Yes, there're better ways to handle the API key but, since it's free, I will change it in the future.

3. Run the main application:
```bash
python fibler.py
```

## Project Structure

```
├── core/
│   ├── formatters/
│   │   └── impexp.py
│   ├── analyzer.py
│   ├── disassembler.py
│   ├── parser.py
│   └── vt.py
│
├── gui/
│   ├── fonts/
│   │   ├── IosevkaTermNerdFont-Bold
│   │   ├── IosevkaTermNerdFont-Medium
│   │   └── IosevkaTermNerdFont-Regular
│   ├── styles/
│   │   └── default.py
│   ├── widgets/
│   │   ├── exports.py
│   │   ├── imports.py
│   │   ├── libraries.py
│   │   └── triage.py
│   └── windows/
│       ├── main.py
│       └── welcome.py
│
├── fibler.py
├── README.md
└── requirements.txt
```

## Memory Management

When running the application, you may notice nanobind reporting leaked instances of LIEF's type system:
```
nanobind: leaked X instances!
 - leaked instance of type "lief._lief.VA_TYPES"
 - leaked instance of type "lief._lief.FORMATS"
```

These messages are **expected behavior** and can be safely ignored. They represent LIEF's static type system initialization, which:
- Are one-time allocations that don't grow with usage
- Get automatically cleaned up when Python exits
- Are required for Python-C++ interoperability

These are not memory leaks in your binary analysis workflow and won't affect the application's performance or memory usage over time.

## Contributing

Feel free to open issues and pull requests for any improvements or bug fixes.