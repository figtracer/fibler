from capstone import *
from typing import List, Dict, Any


class Disassembler:
    def __init__(self):
        self.little_endian_disassembler = None
        self.big_endian_disassembler = None

    def disassemble(
        self, bytes: bytes, start_address: int, endianness: str
    ) -> List[Dict[str, Any]]:
        """
        disassembles binary content into instructions.

        args:
            + bytes (bytes): raw binary content to disassemble
            + start_address (int): starting address for disassembly
            + endianness (str): "Little Endian" or "Big Endian"

        returns:
            + list of dictionaries containing:
                - address: instruction address
                - mnemonic: instruction mnemonic
                - op_str: operand string
        """
        if endianness == "Little Endian":
            return self.disassemble_little_endian(bytes, start_address)
        elif endianness == "Big Endian":
            return self.disassemble_big_endian(bytes, start_address)

    def disassemble_little_endian(
        self, bytes: bytes, start_address: int
    ) -> List[Dict[str, Any]]:
        md = self._get_little_endian_settings()
        return self._process_instructions(md.disasm(bytes, start_address))

    def disassemble_big_endian(
        self, bytes: bytes, start_address: int
    ) -> List[Dict[str, Any]]:
        md = self._get_big_endian_settings()
        return self._process_instructions(md.disasm(bytes, start_address))

    def _get_little_endian_settings(self):
        if not self.little_endian_disassembler:
            self.little_endian_disassembler = Cs(
                CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN
            )
        return self.little_endian_disassembler

    def _get_big_endian_settings(self):
        if not self.big_endian_disassembler:
            self.big_endian_disassembler = Cs(
                CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_BIG_ENDIAN
            )
        return self.big_endian_disassembler

    @staticmethod
    def _process_instructions(disasm_result) -> List[Dict[str, Any]]:
        instructions = []

        for instruction in disasm_result:
            instructions.append(
                {
                    "address": instruction.address,
                    "mnemonic": instruction.mnemonic,
                    "op_str": instruction.op_str,
                }
            )

        return instructions
