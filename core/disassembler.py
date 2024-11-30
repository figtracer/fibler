from capstone import (
    Cs,
    CS_ARCH_ARM64,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_BIG_ENDIAN,
)
from typing import List, Dict, Any


class Disassembler:
    def __init__(self):
        self.arm64_le_disasm = None
        self.arm64_be_disasm = None
        self.arm32_le_disasm = None
        self.arm32_be_disasm = None

    def disassemble(
        self,
        arch: str,
        bytes: bytes,
        start_address: int,
        endianness: str,
    ) -> List[Dict[str, Any]]:
        if endianness not in ("LITTLE", "BIG"):
            return []

        if arch in ("AARCH64", "ARM64"):
            if endianness == "LITTLE":
                md = self._get_arm64_le_settings()
            else:
                md = self._get_arm64_be_settings()
        elif arch == "ARM":  # ARM32
            if endianness == "LITTLE":
                md = self._get_arm32_le_settings()
            else:
                md = self._get_arm32_be_settings()

        return self._process_instructions(md.disasm(bytes, start_address))

    def _get_arm64_le_settings(self):
        if not self.arm64_le_disasm:
            self.arm64_le_disasm = Cs(
                CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN
            )
        return self.arm64_le_disasm

    def _get_arm64_be_settings(self):
        if not self.arm64_be_disasm:
            self.arm64_be_disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_BIG_ENDIAN)
        return self.arm64_be_disasm

    def _get_arm32_le_settings(self):
        if not self.arm32_le_disasm:
            self.arm32_le_disasm = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        return self.arm32_le_disasm

    def _get_arm32_be_settings(self):
        if not self.arm32_be_disasm:
            self.arm32_be_disasm = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_BIG_ENDIAN)
        return self.arm32_be_disasm

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
