import lief
import logging
from typing import Dict, Any
from core.vt import VirusTotalScanner
from core.formatters.impexp import ImpExpFormatter
from core.formatters.sections import SectionsFormatter
from core.formatters.libraries import LibrariesFormatter

# these leaks were expected behaviour but removed from the output to prevent confusion in the UI
lief.disable_leak_warning()

logger = logging.getLogger(__name__)


class Parser:
    def __init__(self):
        self.scanner = VirusTotalScanner()
        self.impexp_formatter = ImpExpFormatter()
        self.sections_formatter = SectionsFormatter()
        self.libraries_formatter = LibrariesFormatter()
        self.binary: lief.Binary = None

    def __del__(self):
        try:
            if not self.binary:
                return
            self.binary = None

            self.scanner = None
            self.impexp_formatter = None
            self.sections_formatter = None
            self.libraries_formatter = None
        except Exception as e:
            logger.error(f"Error during Parser cleanup: {e}")

    def parse(self, binary_path: str) -> Dict[str, Any]:
        # cleanup
        if self.binary:
            self.binary = None

        self.binary = lief.parse(binary_path)

        if isinstance(self.binary, lief.MachO.Binary):
            return self._parse_macho(self.binary, binary_path)
        elif isinstance(self.binary, lief.ELF.Binary):
            return self._parse_elf(self.binary, binary_path)
        else:
            raise ValueError("Unsupported file format")

    def _parse_macho(self, binary: lief.Binary, binary_path: str) -> Dict[str, Any]:
        file_format = "MACH-O"

        if not binary.get_section("__text"):
            raise ValueError(f"{binary} doesn't have a __text section")
        text_section = binary.get_section("__text")
        va = text_section.virtual_address
        content = bytes(text_section.content)

        if not binary.header:
            raise ValueError(f"{binary} doesn't have a header")
        magic = hex(binary.header.magic)
        cpu_type = str(binary.header.cpu_type).split(".")[-1]
        file_type = str(binary.header.file_type).split(".")[-1]
        flags_list = binary.header.flags_list

        endianness = None
        if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            endianness = "LITTLE"

        total, positives = self.scanner.get_av_reports(binary_path)

        # iterators
        libraries = []
        if binary.libraries:
            raw_libraries = [str(library) for library in binary.libraries]
            libraries = self.libraries_formatter.process_libraries(
                raw_libraries, file_format
            )

        imports = []
        if binary.imported_symbols:
            raw_imports = [str(symbol) for symbol in binary.imported_symbols]
            imports = self.impexp_formatter.process_impexp(raw_imports, file_format)

        exports = []
        if binary.exported_symbols:
            raw_exports = [str(symbol) for symbol in binary.exported_symbols]
            exports = self.impexp_formatter.process_impexp(raw_exports, file_format)

        sections = []
        if binary.sections:
            raw_sections = [str(section) for section in binary.sections]
            sections = self.sections_formatter.process_sections(
                raw_sections, file_format
            )

        return {
            "file_format": file_format,
            "architecture": cpu_type,
            "file_type": file_type,
            "magic": magic,
            "endianness": endianness,
            "flags": flags_list,
            "va": va,
            "content": content,
            "total": total,
            "positives": positives,
            "libraries": libraries,
            "imports": imports,
            "exports": exports,
            "sections": sections,
        }

    def _parse_elf(self, binary: lief.Binary, binary_path: str) -> Dict[str, Any]:
        file_format = "ELF"

        if not binary.get_section(".text"):
            raise ValueError(f"{binary} does not contain a .text section")

        text_section = binary.get_section(".text")
        va = text_section.virtual_address
        content = text_section.content

        total, positives = self.scanner.get_av_reports(binary_path)

        if not binary.header:
            raise ValueError(f"{binary} does not contain a Header")

        get_endianness = binary.header.identity_data
        if get_endianness == lief.ELF.Header.ELF_DATA.LSB:
            endianness = "LITTLE"
            byteorder = "little"
        elif get_endianness == lief.ELF.Header.ELF_DATA.MSB:
            endianness = "BIG"
            byteorder = "big"
        else:
            raise ValueError(f"Unknown endianness in {binary}")

        magic = hex(int.from_bytes((binary.header.identity[:4]), byteorder=byteorder))
        file_type = str(binary.header.file_type).split(".")[-1]
        flags_list = binary.header.flags_list

        architecture = str(binary.header.machine_type).split(".")[-1]

        libraries = []
        if binary.dynamic_entries:
            raw_libraries = [
                str(lib)
                for lib in binary.dynamic_entries
                if isinstance(lib, lief.ELF.DynamicEntryLibrary)
            ]
            libraries = self.libraries_formatter.process_libraries(
                raw_libraries, file_format
            )

        imports = []
        if binary.imported_symbols:
            raw_imports = [str(symbol) for symbol in binary.imported_symbols]
            imports = self.impexp_formatter.process_impexp(raw_imports, file_format)

        exports = []
        if binary.exported_symbols:
            raw_exports = [str(symbol) for symbol in binary.exported_symbols]
            exports = self.impexp_formatter.process_impexp(raw_exports, file_format)

        sections = []
        if binary.sections:
            raw_sections = [str(section) for section in binary.sections]
            sections = self.sections_formatter.process_sections(
                raw_sections, file_format
            )

        return {
            "file_format": file_format,
            "architecture": architecture,
            "file_type": file_type,
            "magic": magic,
            "endianness": endianness,
            "flags": flags_list,
            "va": va,
            "content": content,
            "total": total,
            "positives": positives,
            "libraries": libraries,
            "imports": imports,
            "exports": exports,
            "sections": sections,
        }
