import lief
from typing import Dict, Any
from core.vt import VirusTotalScanner
from core.formatters.impexp import ImpExpFormatter


class Parser:
    def __init__(self):
        self.scanner = VirusTotalScanner()
        self.import_formatter = ImpExpFormatter()
        self.binary = None

    def __del__(self):
        try:
            if self.binary:
                # cleanup iterators
                if hasattr(self.binary, "imported_symbols"):
                    self.binary.imported_symbols = None
                if hasattr(self.binary, "exported_symbols"):
                    self.binary.exported_symbols = None
                if hasattr(self.binary, "libraries"):
                    self.binary.libraries = None

                # cleanup header refs
                if hasattr(self.binary, "header"):
                    if hasattr(self.binary.header, "flags_list"):
                        self.binary.header.flags_list = None

                # cleanup binary ifself
                self.binary = None
        except:
            pass

    def parse(self, binary_path: str) -> Dict[str, Any]:
        self.binary = lief.parse(binary_path)

        if isinstance(self.binary, lief.MachO.Binary):
            return self._parse_macho(self.binary, binary_path)
        elif isinstance(self.binary, lief.ELF.Binary):
            return self._parse_elf(self.binary, binary_path)
        else:
            raise ValueError("Unsupported file format")

    def _parse_macho(self, binary: lief.Binary, binary_path: str) -> Dict[str, Any]:
        file_format = "MACH-O"
        magic = hex(binary.header.magic)
        cpu_type = str(binary.header.cpu_type).split(".")[-1]
        file_type = str(binary.header.file_type).split(".")[-1]
        flags_list = binary.header.flags_list
        reserved = binary.header.reserved
        nb_cmds = binary.header.nb_cmds
        libraries = binary.libraries

        endianness = None
        total, positives = self.scanner.get_av_reports(binary_path)

        text_section = binary.get_section("__text")
        if not text_section:
            raise ValueError(f"{binary} does not contain a __text section")

        if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            endianness = "Little Endian"

        imports = []
        if binary.imported_symbols:
            raw_imports = [str(symbol) for symbol in binary.imported_symbols]
            imports = self.import_formatter.process_imports(raw_imports, file_format)

        exports = []
        for symbol in binary.exported_symbols:
            raw_exports = [str(symbol) for symbol in binary.exported_symbols]
            exports = self.import_formatter.process_imports(raw_exports, file_format)

        return {
            "file_format": file_format,
            "magic": magic,
            "architecture": cpu_type,
            "file_type": file_type,
            "flags": flags_list,
            "nb_cmds": nb_cmds,  # number of load commands
            "reserved": reserved,  # reserved value
            "content": bytes(text_section.content),
            "text_section_start": text_section.virtual_address,
            "endianness": endianness,
            "total": total,
            "positives": positives,
            "libraries": libraries,
            "imports": imports,
            "exports": exports,
        }

    def _parse_elf(self, binary: lief.Binary, binary_path: str) -> Dict[str, Any]:
        # check endianness first to read magic correctly
        get_endianness = binary.header.identity_data
        if get_endianness == lief.ELF.Header.ELF_DATA.LSB:
            endianness = "Little Endian"
            byteorder = "little"
        elif get_endianness == lief.ELF.Header.ELF_DATA.MSB:
            endianness = "Big Endian"
            byteorder = "big"
        else:
            raise ValueError(f"Unkmown endianness in {binary}")

        file_format = "ELF"
        magic = hex(int.from_bytes((binary.header.identity[:4]), byteorder=byteorder))
        machine_type = str(binary.header.machine_type).split(".")[-1]
        file_type = str(binary.header.file_type).split(".")[-1]
        flags_list = binary.header.flags_list
        nb_sections = binary.header.numberof_sections
        nb_segments = binary.header.numberof_segments
        program_header_offset = binary.header.program_header_offset  # segments table
        entrypoint = binary.header.entrypoint
        total, positives = self.scanner.get_av_reports(binary_path)

        text_section = binary.get_section(".text")
        if not text_section:
            raise ValueError(f"{binary} does not contain a .text section")

        get_endianness = binary.header.identity_data
        if get_endianness == lief.ELF.Header.ELF_DATA.LSB:
            endianness = "Little Endian"
        elif get_endianness == lief.ELF.Header.ELF_DATA.MSB:
            endianness = "Big Endian"
        else:
            raise ValueError("Couldn't get endianness")

        libraries = []
        for entry in binary.dynamic_entries:
            if isinstance(entry, lief.ELF.DynamicEntryLibrary):
                libraries.append(str(entry.name))

        imports = []
        if binary.imported_symbols:
            raw_imports = [str(symbol) for symbol in binary.imported_symbols]
            imports = self.import_formatter.process_imports(raw_imports, file_format)

        exports = []
        for symbol in binary.exported_symbols:
            raw_exports = [str(symbol) for symbol in binary.exported_symbols]
            exports = self.import_formatter.process_imports(raw_exports, file_format)

        return {
            "file_format": file_format,
            "magic": magic,
            "architecture": machine_type,  # architecture
            "file_type": file_type,  # executable, library...
            "flags": flags_list,  # processor flags
            "program_header_offset": program_header_offset,
            "nb_sections": nb_sections,  # nunber of sections
            "nb_segments": nb_segments,  # number of segments
            "content": bytes(text_section.content),
            "text_section_start": text_section.virtual_address,
            "entrypoint": entrypoint,
            "endianness": endianness,
            "total": total,
            "positives": positives,
            "libraries": libraries,
            "imports": imports,
            "exports": exports,
        }
