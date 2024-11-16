from core.disassembler import disassemble_arm64_little
from core.parser import extract_text_section

"""
analyzes an arbitrary binary

args:
+ file_path(str): file path to binary

returns:
+ (dict): dictionary that contains all the instructions + start address (base address)
"""

def analyze_binary(file_path: str) -> dict:
    text_data, text_start_address = extract_text_section(file_path)

    instructions = disassemble_arm64_little(text_data, text_start_address)

    return {
        "instructions": instructions,
        "start_address": text_start_address
    }