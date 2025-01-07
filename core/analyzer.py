from core.disassembler import Disassembler
from core.parser import Parser
from typing import Dict, Any


class Analyzer:
    def __init__(self, file_path: str):
        print(f"Initializing Analyzer with file: {file_path}")
        self.file_path = file_path
        self.binary_info = None
        try:
            print("Creating Parser instance")
            self.parser: Parser = Parser()
            print("Creating Disassembler instance")
            self.disassembler: Disassembler = Disassembler()
        except Exception as e:
            print(f"Error during initialization: {e}")
            raise

    def analyze(self) -> Dict[str, Any]:
        print("Starting analysis")
        try:
            if self.parser is None:
                raise ValueError("Parser is not initialized")

            print("About to parse binary")
            self.binary_info = self.parser.parse(self.file_path)
            if not self.binary_info:
                raise ValueError("Failed to get binary information")

            print("Binary info obtained")

            if not self.disassembler:
                raise ValueError("Disassembler is not initialized")

            print("About to disassemble")
            instructions = self.disassembler.disassemble_all_sections(self.binary_info)

            # initialize fallback if the binary is obfuscated / no sections.
            fallback_instructions = None
            if not instructions:
                print("No sections found\n\tAttempting fallback disassembly...")
                fallback_instructions = self.disassembler.disassemble(
                    self.binary_info["architecture"],
                    self.binary_info["content"],
                    self.binary_info["va"],
                    self.binary_info["endianness"],
                )

            if fallback_instructions:
                instructions = fallback_instructions
                print(f"Fallback disassembly found {len(instructions)} instructions")

            return {
                "binary_info": self.binary_info,
                "instructions": instructions,
                "va": self.binary_info["va"],
            }

        except Exception as e:
            print(f"Error in analyze(): {e}")
            raise
