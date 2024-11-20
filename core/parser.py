import lief
from typing import Dict, Any
from core.vt import VirusTotalScanner


class Parser:
    def __init__(self):
        self.scanner = VirusTotalScanner()

    def parse(self, binary_path: str) -> Dict[str, Any]:
        """
        parses a binary file and extracts its metadata.

        args:
            + binary_path (str): Path to the binary file

        returns:
            + Dict containing binary metadata including:
                - file format, magic, architecture, flags
                - section information and contents
                - endianness and other format-specific data

        raises:
            ValueError: if file format is unsupported
        """
        binary = lief.parse(binary_path)

        if isinstance(binary, lief.MachO.Binary):
            return self._parse_macho(binary, binary_path)
        elif isinstance(binary, lief.ELF.Binary):
            return self._parse_elf(binary, binary_path)
        else:
            raise ValueError("Unsupported file format")

    def _parse_macho(self, binary: lief.Binary, binary_path: str) -> Dict[str, Any]:
        """
        parses a Mach-O binary format file.

        args:
            + binary (lief.Binary): LIEF Binary object
            + binary_path (str): Path to the binary file

        returns:
            + Dict containing Mach-O specific information:
                - magic number, CPU type/subtype
                - flags, commands, sections
                - endianness and file type
                - VirusTotal scan results

        raises:
            ValueError: if __text section is missing
        """
        magic = hex(binary.header.magic)
        cpu_type = str(binary.header.cpu_type).split(".")[-1]
        cpu_subtype = str(binary.header.cpu_subtype).split(".")[-1]
        file_type = str(binary.header.file_type).split(".")[-1]
        flags_list = binary.header.flags_list
        reserved = binary.header.reserved
        nb_cmds = binary.header.nb_cmds
        endianness = None
        total, positives = self.scanner.get_av_reports(binary_path)

        text_section = binary.get_section("__text")
        if not text_section:
            raise ValueError(f"{binary} does not contain a __text section")

        if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            endianness = "Little Endian"

        return {
            "file_format": "Mach-O",
            "magic": magic,
            "architecture": cpu_type,
            "cpu_subtype": cpu_subtype,
            "file_type": file_type,
            "flags": flags_list,
            "nb_cmds": nb_cmds,  # number of load commands
            "reserved": reserved,  # reserved value
            "content": bytes(text_section.content),
            "text_section_start": text_section.virtual_address,
            "endianness": endianness,
            "total": total,
            "positives": positives,
        }

    def _parse_elf(self, binary: lief.Binary, binary_path: str) -> Dict[str, Any]:
        """
        parses an ELF binary format file.

        args:
            + binary (lief.Binary): LIEF Binary object
            + binary_path (str): path to the binary file

        returns:
            + Dict containing ELF specific information:
                - magic number
                - flags, sections, segments
                - endianness and file type
                - entrypoint, program_header_offset
                - VirusTotal scan results

        raises:
            ValueError: if __text section is missing
        """
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

        return {
            "file_format": "ELF",
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
        }
