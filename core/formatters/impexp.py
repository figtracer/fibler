from typing import List


class ImpExpFormatter:
    @staticmethod
    def format_import(entry: str, binary_format: str) -> List:
        if binary_format.upper() == "ELF":
            # check if it's in the format "function @GLIBC_X.Y (FUNC/...)"
            if "@GLIBC_" in entry:
                if "@@GLIBC_" in entry:
                    # strtok@@GLIBC_2.17 (FUNC/GLOBAL): --> 'strtok', 'GLIBC_2.17 (FUNC/GLOBAL...)'
                    function_name = entry.split("@@")[0]
                    # 'strtok@@GLIBC_2.17 (FUNC/GLOBAL): --> 'strtok@@', '2.17 FUNC/GLOBAL...'
                    version = entry.split("GLIBC_")[1]
                    version = version.split(" ")[0].strip()
                    return f"{function_name}@GLIBC_{version}"
                else:
                    # split on space to separate function name and rest
                    parts = entry.split(" ")
                    # take the first two parts (function name and @GLIBC version)
                    return " ".join(parts[:2])

            # check if it's in the format "function (FUNC/GLOBAL): address (0x00)GLIBC_X.Y"
            elif " (FUNC/" in entry and "GLIBC_" in entry:
                function_name = entry.split(" (FUNC/")[0].strip()
                if "GLIBC_" in entry:
                    version = entry.split("GLIBC_")[1]
                    version = version.split("(")[0].strip()
                    return f"{function_name}@GLIBC_{version}"
                return function_name

            # check if it's in the format "function (FUNC/GLOBAL)"
            elif " (FUNC/" in entry:
                return entry.split(" (FUNC/")[0].strip()

            # check if it's in the format "function (XYZ)..."
            elif "(" in entry:
                return entry.split("(")[0].strip()

            return entry.strip()

        elif binary_format.upper() == "MACH-O":
            if entry.startswith("name="):
                return entry.split("name=")[1].split(",")[0].strip()
            return entry.strip()

        return entry

    @staticmethod
    def process_impexp(imports_list: list, binary_format: str) -> List:
        return [
            import_info
            for import_info in (
                ImpExpFormatter.format_import(imp, binary_format)
                for imp in imports_list
            )
            if import_info is not None
        ]
