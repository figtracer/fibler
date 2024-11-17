from core.disassembler import disassemble
from core.parser import extract_program_bytes

"""
analyzes an arbitrary binary

args:
+ file_path(str): file path to binary

returns:
+ (dict): dictionary that contains all the instructions + start address (base address)
"""


def analyze_binary(file_path: str) -> dict:
    text_data, text_start_address, endianness = extract_program_bytes(file_path)
    if not text_data or endianness:
        raise ValueError("Failed to extract data or endianness")

    instructions = disassemble(text_data, text_start_address, endianness)
    if not instructions:
        raise ValueError("Couldn't get disassembled instructions")

    return {"instructions": instructions, "start_address": text_start_address}
