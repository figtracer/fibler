#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "elf_parser.hpp"
#include "elf_types.hpp"

namespace py = pybind11;

PYBIND11_MODULE(native_parser, m)
{
    py::class_<ElfParser>(m, "ElfParser")
        .def(py::init<>())
        .def("parse_file", &ElfParser::parse_file);

    py::class_<ElfInfo>(m, "ElfInfo")
        .def_readonly("file_format", &ElfInfo::file_format)
        .def_readonly("architecture", &ElfInfo::architecture)
        .def_readonly("file_type", &ElfInfo::file_type)
        .def_readonly("magic", &ElfInfo::magic)
        .def_readonly("endianness", &ElfInfo::endianness)
        .def_readonly("va", &ElfInfo::va)
        .def_readonly("content", &ElfInfo::content)
        .def_readonly("total", &ElfInfo::total)
        .def_readonly("positives", &ElfInfo::positives)
        .def_readonly("imports", &ElfInfo::imports)
        .def_readonly("exports", &ElfInfo::exports)
        .def_readonly("sections", &ElfInfo::sections);

    py::class_<Section>(m, "ELFSection")
        .def_readonly("name", &Section::name)
        .def_readonly("va", &Section::va)
        .def_readonly("size", &Section::size)
        .def_readonly("content", &Section::content)
        .def_readonly("flags", &Section::flags);
}
