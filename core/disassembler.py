from capstone import *
from typing import List


# dissassemble() bytes
def disassemble(bytes: bytes, start_address: int, endianness: str) -> List:
    if endianness == "Little Endian":
        return disassemble_arm64_little(bytes, start_address)
    elif endianness == "Big Endian":
        return disassemble_arm64_big(bytes, start_address)


"""
disassembles arm64 little/big endian binary
...i wonder who will disassemble a big endian binary nowadays

args:
+ binary(bytes): the raw bytes to disassemble
+ start_address(int): the starting address 

returns:
+ instructions(list): a list of disassembled instructions
"""


def disassemble_arm64_little(bytes: bytes, start_address: int) -> List:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
    instructions = []

    for instruction in md.disasm(bytes, start_address):
        instructions.append(
            {
                "address": instruction.address,
                "mnemonic": instruction.mnemonic,
                "op_str": instruction.op_str,
            }
        )

    return instructions


def disassemble_arm64_big(bytes: bytes, start_address: int) -> List:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_BIG_ENDIAN)
    instructions = []

    for instruction in md.disasm(bytes, start_address):
        instructions.append(
            {
                "address": instruction.address,
                "mnemonic": instruction.mnemonic,
                "op_str": instruction.op_str,
            }
        )

    return instructions
