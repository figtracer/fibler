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

    if not binary_info:
        raise ValueError("Failed to get binary information")

    instructions = disassemble(
        binary_info["content"],
        binary_info["text_section_start"],
        binary_info["endianness"],
    )

    if not instructions:
        raise ValueError("Couldn't get disassembled instructions")

    return {
        "binary_info": binary_info,
        "instructions": instructions,
        "text_section_start": binary_info["text_section_start"],
    }
