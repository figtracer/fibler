import logging
from capstone import (
    Cs,
    CS_ARCH_ARM64,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_BIG_ENDIAN,
)
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class Disassembler:
    def __init__(self):
        self.arm64_le_disasm = None
        self.arm64_be_disasm = None
        self.arm32_le_disasm = None
        self.arm32_be_disasm = None

    def disassemble_all_sections(self, info) -> Dict[str, List[Dict[str, Any]]]:
        instructions = {}

        if not info["executable_sections"]:
            print("No executable sections found. Attempting fallback disassembly...")
            try:
                # Create a pseudo-section for the entire binary
                arch = "AArch64" if info["architecture"] == "AArch64" else "ARM"
                all_instructions = self.disassemble(
                    arch,
                    bytes(info["content"]),
                    info["va"],
                    info["endianness"],
                )
                if all_instructions:
                    instructions[".fallback"] = all_instructions
                    print(
                        f"Fallback disassembly found {len(all_instructions)} instructions"
                    )
                else:
                    print("Fallback disassembly found no instructions")
            except Exception as e:
                logger.error(f"Fallback disassembly failed: {str(e)}")
                return {"Error": []}
        else:
            for section in info["executable_sections"]:
                if not section.content:
                    print(f"Skipping section: {section}")
                    continue

                try:
                    code_bytes = bytes(section.content)
                    if not code_bytes:
                        print(f"Skipping empty section: {section.name}")
                        continue

                    arch = "AArch64" if info["architecture"] == "AArch64" else "ARM"
                    section_instructions = self.disassemble(
                        arch,
                        code_bytes,
                        section.va,
                        info["endianness"],
                    )

                    instructions[section.name] = section_instructions

                except Exception as e:
                    logger.error(
                        f"Failed to disassemble section {section.name}: {str(e)}"
                    )
                    continue

        if not instructions:
            return {"Error": []}

        return instructions

    def disassemble(
        self, arch: str, bytes: bytes, start_address: int, endianness: str
    ) -> List[Dict[str, Any]]:
        if endianness not in ("LITTLE", "BIG"):
            logger.error(f"[ERROR] Invalid endianness: {endianness}")

        if not bytes:
            return []

        try:
            md = None
            if arch == "AArch64":
                if endianness == "LITTLE":
                    md = self._get_arm64_le_settings()
                else:  # BIG
                    md = self._get_arm64_be_settings()
            elif arch == "ARM":
                if endianness == "LITTLE":
                    md = self._get_arm32_le_settings()
                else:  # BIG
                    md = self._get_arm32_be_settings()

            if md is None:
                logger.error(
                    f"Unsupported architecture: {arch} with endianness {endianness}"
                )

            instructions = []
            for i in range(0, len(bytes), 4):
                chunk = bytes[i : i + 4]
                if len(chunk) == 4:  # only process complete instructions
                    try:
                        insts = list(md.disasm(chunk, start_address + i))
                        if insts:
                            instructions.extend(insts)
                    except Exception as e:
                        logger.error(
                            f"Failed to disassemble at offset {hex(i)}: {str(e)}"
                        )
                        continue

            if not instructions:
                logger.error("No instructions were disassembled")

            processed = self._process_instructions(instructions)
            return processed

        except Exception as e:
            logger.error(f"Disassembly failed: {str(e)}")
            return []

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
