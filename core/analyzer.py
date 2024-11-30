import logging
from core.disassembler import Disassembler
from core.parser import Parser
from typing import Dict, Any

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.binary_info = None
        self.parser: Parser = Parser()
        self.disassembler: Disassembler = Disassembler()

    def __del__(self):
        try:
            self.binary_info = None
            self.parser = None
            self.disassembler = None
        except Exception as e:
            logger.error(f"Error during Analyzer cleanup: {e}")

    def analyze(self) -> Dict[str, Any]:
        if self.parser is None:
            raise ValueError("Parser is not initialized")

        # cleanup
        self.binary_info = None

        self.binary_info = self.parser.parse(self.file_path)
        if not self.binary_info:
            raise ValueError("Failed to get binary information")

        if not self.disassembler:
            raise ValueError("Disassembler is not initialized")

        instructions = self.disassembler.disassemble(
            self.binary_info["architecture"],
            self.binary_info["content"],
            self.binary_info["va"],
            self.binary_info["endianness"],
        )

        if not instructions:
            raise ValueError("Couldn't get disassembled instructions")

        return {
            "binary_info": self.binary_info,
            "instructions": instructions,
            "va": self.binary_info["va"],
        }
