from typing import List


class SectionsFormatter:
    @staticmethod
    def format_section(entry: str, binary_format: str) -> List:
        if binary_format.upper() == "MACH-O":
            if entry.startswith("name="):
                name = entry.split("name=")[1].split(",")[0].strip()
                start_address = int(
                    entry.split("address=")[1].split(",")[0].strip(), 16
                )
                size = int(entry.split("size=")[1].split(" ")[0].strip(), 16)
                type = entry.split("type=")[1].split(",")[0].strip()

                end_address = hex(start_address + size)

                return f"{name:<20}{hex(start_address)}-{end_address:<12}{type}"
        elif binary_format.upper() == "ELF":
            if entry.startswith("."):
                name = entry.split(" ")[0].strip()
                start_address = int(entry.split(" ")[2].split("/")[0].strip(), 16)
                size = int(entry.split(" ")[3].strip(), 16)
                type = entry.split(" ")[1].split("()")[0].strip()

                end_address = hex(start_address + size)
                start_address = hex(start_address)

                return f"{name:<20}{start_address:>10}-{end_address:<12}{type}"

    @staticmethod
    def process_sections(sections_list: list, binary_format: str) -> List:
        return [
            section
            for section in (
                SectionsFormatter.format_section(section, binary_format)
                for section in sections_list
            )
            if section is not None
        ]
