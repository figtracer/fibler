# parser.py
import logging
from typing import Dict, Any
from .vt import VirusTotalScanner
from native_parser import ElfParser  # type: ignore

SHF_EXECINSTR = 0x4

logger = logging.getLogger(__name__)


class Parser:
    def __init__(self):
        self.native_parser = ElfParser()
        self.scanner = VirusTotalScanner()
        self.binary = None

    def __del__(self):
        try:
            self.binary = None
            self.native_parser = None
        except Exception as e:
            logger.error(f"Error during Parser cleanup: {e}")

    def parse(self, binary_path: str) -> Dict[str, Any]:
        if self.binary:
            self.binary = None

        try:
            total, positives = self.scanner.get_av_reports(binary_path)
            info = self.native_parser.parse_file(binary_path)

            return {
                "content": bytes(info.content),
                "file_format": info.file_format,
                "architecture": info.architecture,
                "file_type": info.file_type,
                "magic": info.magic,
                "endianness": info.endianness,
                "va": info.va,
                "total": total,
                "positives": positives,
                "imports": info.imports,
                "exports": info.exports,
                "sections": [
                    f"{section.name:<20} 0x{section.va:08x}-0x{section.va+section.size-4:08x} Flags: 0x{section.flags:x}"
                    for section in sorted(info.sections, key=lambda s: s.va)
                    if section.name
                ],
                "executable_sections": [
                    s for s in info.sections if s.flags & SHF_EXECINSTR
                ],
            }

        except Exception as e:
            logger.error(f"Error parsing binary: {e}")
            raise
