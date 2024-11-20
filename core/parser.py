import lief
from typing import Dict, Any
from core.vt import VirusTotalScanner

"""
extracts binary information including header parms, text section and endianness
Currently supports Mach-O and ELF file formats

args:
+ binary_path(str): path to binary file

returns:
+ dict[str, Any]: 
    - magic: magic number
    - cpu_type: CPU architecture    
    - cpu_subtype: CPU subtype
    - file_type: type of the file
    - flags_list: binary flags
    - nb_cmds: number of commands (Mach-O) or number of sections (ELF)
    - sizeof_cmds: size of commands (Mach-O) or size of section headers (ELF)
    - reserved: reserved bytes (Mach-O only)
    - content: text section content
    - va: virtual address
    - endianness: binary endianness
"""


def parser(binary_path: str) -> Dict[str, Any]:
    binary = lief.parse(binary_path)
    scanner = VirusTotalScanner()
    total, positives = scanner.get_av_reports(binary_path)

    # MACH-O
    if isinstance(binary, lief.MachO.Binary):
        # extracting header params
        magic = hex(binary.header.magic)
        cpu_type = str(binary.header.cpu_type).split(".")[-1]
        cpu_subtype = str(binary.header.cpu_subtype).split(".")[-1]
        file_type = str(binary.header.file_type).split(".")[-1]
        flags_list = binary.header.flags_list
        reserved = binary.header.reserved
        endianness = None

        # sections
        nb_cmds = binary.header.nb_cmds

        # get __text
        text_section = binary.get_section("__text")
        if not text_section:
            raise ValueError(f"{binary} does not contain a __text section")

        # check endianness (mach-o arm64 binaries are always little endian)
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

    # ELF
    if isinstance(binary, lief.ELF.Binary):
        # check endianness first to read 'magic' correctly
        get_endianness = binary.header.identity_data
        if get_endianness == lief.ELF.Header.ELF_DATA.LSB:
            endianness = "Little Endian"
            byteorder = "little"
        elif get_endianness == lief.ELF.Header.ELF_DATA.MSB:
            endianness = "Big Endian"
            byteorder = "big"
        else:
            raise ValueError(f"Unkmown endianness in {binary}")

        # extracting header params
        magic = hex(int.from_bytes((binary.header.identity[:4]), byteorder=byteorder))
        machine_type = str(binary.header.machine_type).split(".")[-1]
        file_type = str(binary.header.file_type).split(".")[-1]
        flags_list = binary.header.flags_list

        # sections/segments
        nb_sections = binary.header.numberof_sections
        nb_segments = binary.header.numberof_segments
        program_header_offset = binary.header.program_header_offset  # segments table

        # binary entrypoint
        entrypoint = binary.header.entrypoint

        # get .text section
        text_section = binary.get_section(".text")
        if not text_section:
            raise ValueError(f"{binary} does not contain a .text section")

        # check endianness
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
