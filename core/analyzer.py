from core.disassembler import disassemble
from core.parser import parser
from typing import Dict, Any

"""
analyzes an arbitrary binary

args:
+ file_path(str): file path to binary

returns:
+ dict[str, Any]: 
    - instructions: list of disassembled instructions
    - start_address: binary's start address
"""


def analyze(file_path: str) -> Dict[str, Any]:
    binary_info = parser(file_path)

    text_data = binary_info["content"]
    text_start_address = binary_info["va"]
    endianness = binary_info["endianness"]

    if not (text_data or endianness or text_start_address):
        raise ValueError("Failed to extract data or endianness")

    instructions = disassemble(text_data, text_start_address, endianness)
    if not instructions:
        raise ValueError("Couldn't get disassembled instructions")

    return {"instructions": instructions, "start_address": text_start_address}
