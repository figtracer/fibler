from core.disassembler import Disassembler
from core.parser import Parser
from typing import Dict, Any
import gc


class Analyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.binary_info = None
        self.parser = Parser()
        self.disassembler = Disassembler()

    def __del__(self):
        try:
            if hasattr(self, "binary_info"):
                self.binary_info = None
            self.binary_info = None
            if hasattr(self, "parser"):
                self.parser = None
        except:
            pass

    def analyze(self) -> Dict[str, Any]:
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
