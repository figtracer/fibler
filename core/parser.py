import lief


"""
extracts text section (program code) + endianness from an arbitrary binary
only supports Mach-O and ELF file formats

args:
+ binary (str): path to binary

returns:
+ (tuple): tuple of the text section's content + section offset)
"""


def extract_program_bytes(binary: str) -> tuple:
    binary = lief.parse(binary)

    # MACH-O
    if isinstance(binary, lief.MachO.Binary):
        # get __text
        text_section = binary.get_section("__text")
        if not text_section:
            raise ValueError(f"{binary} does not contain a __text section")

        # get endianness
        endianness = None
        if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64:
            endianness = "Little Endian"

        return bytes(text_section.content), text_section.virtual_address, endianness

    # ELF
    if isinstance(binary, lief.ELF.Binary):
        # get .text
        text_section = binary.get_section(".text")
        if not text_section:
            raise ValueError(f"{binary} does not contain a .text section")

        # get endianness
        endianness = None
        get_endianness = binary.header.identity_data
        if get_endianness == lief.ELF.Header.ELF_DATA.LSB:
            endianness = "Little Endian"
        elif get_endianness == lief.ELF.Header.ELF_DATA.MSB:
            endianness = "Big Endian"

        return bytes(text_section.content), text_section.virtual_address, endianness
