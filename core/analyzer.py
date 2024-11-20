from core.disassembler import Disassembler
from core.parser import Parser
from typing import Dict, Any


class Analyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.binary_info = None
        self.parser = Parser()
        self.disassembler = Disassembler()

    def analyze(self) -> Dict[str, Any]:
        """
        analyzes a binary file by parsing and disassembling it.

        returns:
            + Dict containing:
                - binary_info: dictionary of parsed binary metadata
                - instructions: list of disassembled instructions
                - text_section_start: starting address of text section

        raises:
            ValueError: if binary parsing or disassembly fails
        """
        self.binary_info = self.parser.parse(self.file_path)
        if not self.binary_info:
            raise ValueError("Failed to get binary information")

        instructions = self.disassembler.disassemble(
            self.binary_info["content"],
            self.binary_info["text_section_start"],
            self.binary_info["endianness"],
        )

        if not instructions:
            raise ValueError("Couldn't get disassembled instructions")

        return {
            "binary_info": self.binary_info,
            "instructions": instructions,
            "text_section_start": self.binary_info["text_section_start"],
        }
