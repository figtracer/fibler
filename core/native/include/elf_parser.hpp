#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include "elf_types.hpp"

struct ElfInfo
{
    // passed to analyzer.py
    std::string file_format;
    std::string architecture;
    std::string file_type;
    std::string magic;
    std::string endianness;
    uint64_t va;
    std::vector<uint8_t> content;
    int total;
    int positives;
    std::vector<std::string> imports;
    std::vector<std::string> exports;
    std::vector<Section> sections;

    const char *dynstr{nullptr};
};

class ElfParser
{
public:
    ElfParser();
    ~ElfParser();

    std::unique_ptr<ElfInfo> parse_file(const std::string &filepath);

private:
    void parse_elf_header_32(const Elf32_Ehdr *header, ElfInfo *info);
    void parse_elf_header_64(const Elf64_Ehdr *header, ElfInfo *info);

    void parse_section_headers_32(const Elf32_Ehdr *header, ElfInfo *info);
    void parse_section_headers_64(const Elf64_Ehdr *header, ElfInfo *info);

    void parse_imports_32(ElfInfo *info);
    void parse_imports_64(ElfInfo *info);

    void parse_exports_32(ElfInfo *info);
    void parse_exports_64(ElfInfo *info);

    std::vector<uint8_t> file_content;
};
