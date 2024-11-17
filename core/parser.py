import lief
from typing import Dict, Any


"""
extracts binary information including header parms, text section and endianness
Currently supports Mach-O and ELF file formats

args:
+ binary(str): path to binary file

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


def parser(binary: str) -> Dict[str, Any]:
    binary = lief.parse(binary)

    # MACH-O
    if isinstance(binary, lief.MachO.Binary):
        # extracting header params
        magic = binary.header.magic
        cpu_type = binary.header.cpu_type
        cpu_subtype = binary.header.cpu_subtype
        file_type = binary.header.file_type
        flags_list = binary.header.flags_list
        nb_cmds = binary.header.nb_cmds
        sizeof_cmds = binary.header.sizeof_cmds
        reserved = binary.header.reserved
        endianness = None

        # get __text
        text_section = binary.get_section("__text")
        if not text_section:
            raise ValueError(f"{binary} does not contain a __text section")

        # check endianness (mach-o arm64 binaries are always little endian)
        if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            endianness = "Little Endian"

        return {
            "magic": magic,
            "cpu_type": cpu_type,
            "cpu_subtype": cpu_subtype,
            "file_type": file_type,
            "flags_list": flags_list,
            "nb_cmds": nb_cmds,
            "sizeof_cmds": sizeof_cmds,
            "reserved": reserved,
            "content": bytes(text_section.content),
            "va": text_section.virtual_address,
            "endianness": endianness,
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
        magic = int.from_bytes((binary.header.identity[:4]), byteorder=byteorder)
        machine_type = binary.header.machine_type
        file_type = binary.header.file_type
        flags = binary.header.processor_flag
        flags_list = binary.header.flags_list
        nb_sections = binary.header.numberof_sections
        section_header_size = binary.header.section_header_size

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
            "magic": hex(magic),
            "cpu_type": machine_type,
            "cpu_subtype": 0,  # elf doesn't have direct cpu subtype
            "file_type": file_type,
            "flags_list": flags_list,
            "nb_cmds": nb_sections,
            "sizeof_cmds": section_header_size,
            "reserved": 0,  # elf doesn't have this field
            "content": bytes(text_section.content),
            "va": text_section.virtual_address,
            "endianness": endianness,
        }
