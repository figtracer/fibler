from typing import List


class LibrariesFormatter:
    @staticmethod
    def format_library(entry: str, binary_format: str) -> str:
        if binary_format.upper() == "MACH-O":
            name = entry.split("name=")[1].split(",")[0].strip()
            return f"{name}"
        elif binary_format.upper() == "ELF":
            name = entry.split(": ")[1].split(" ")[1].strip()
            return f"{name}"       
        else:
            raise ValueError("Unknown file format")

    @staticmethod
    def process_libraries(libraries_list: list, binary_format: str) -> List:
        return [
            library
            for library in (
                LibrariesFormatter.format_library(library, binary_format)
                for library in libraries_list
            )
            if library is not None
        ]
