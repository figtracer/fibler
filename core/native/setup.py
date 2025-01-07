from setuptools import setup, Extension
import pybind11

ext_modules = [
    Extension(
        "native_parser",
        ["src/elf_parser.cpp", "src/bindings.cpp"],
        include_dirs=["include", pybind11.get_include()],
        language="c++",
        extra_compile_args=["-std=c++17"],
    ),
]

setup(
    name="native_parser",
    ext_modules=ext_modules,
    install_requires=["pybind11>=2.10.0"],
    setup_requires=["pybind11>=2.10.0"],
)
