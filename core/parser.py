import lief

"""
extracts text section from an arbitrary binary

args:
+ file_path (str): path to binary

returns:
+ (tuple): tuple of the text section's content + section offset)
"""

def extract_text_section(binary: str) -> tuple:
    binary = lief.parse(binary)

    if isinstance(binary, lief.MachO.Binary):
        text_section = binary.get_section("__text")

        if not text_section:
            raise ValueError("the binary does not contain a __text section")
        return bytes(text_section.content), text_section.virtual_address


              


