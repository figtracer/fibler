#include "elf_parser.hpp"
#include "elf_types.hpp"
#include <fstream>
#include <cstring>
#include <stdexcept>
#include <iostream>

ElfParser::ElfParser() = default;
ElfParser::~ElfParser() = default;

std::unique_ptr<ElfInfo> ElfParser::parse_file(const std::string &filepath)
{
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file)
    {
        throw std::runtime_error("Could not open file");
    }

    auto size = file.tellg();
    file.seekg(0);

    file_content.resize(size);
    file.read(reinterpret_cast<char *>(file_content.data()), size);

    auto info = std::make_unique<ElfInfo>();

    if (file_content.size() < EI_NIDENT ||
        file_content[EI_MAG0] != 0x7F ||
        file_content[EI_MAG1] != 'E' ||
        file_content[EI_MAG2] != 'L' ||
        file_content[EI_MAG3] != 'F')
    {
        throw std::runtime_error("Not a valid ELF file");
    }

    info->file_format = "ELF";
    info->magic = "ELF";
    info->endianness = (file_content[EI_DATA] == ELFDATA2LSB) ? "LITTLE" : "BIG";

    bool is_64bit = file_content[EI_CLASS] == ELFCLASS64;

    if (is_64bit)
    {
        if (file_content.size() < sizeof(Elf64_Ehdr))
        {
            throw std::runtime_error("File too small for ELF64 header");
        }
        auto *header = reinterpret_cast<const Elf64_Ehdr *>(file_content.data());
        parse_elf_header_64(header, info.get());
        parse_section_headers_64(header, info.get());
        parse_imports_64(info.get());
        parse_exports_64(info.get());
    }
    else
    {
        if (file_content.size() < sizeof(Elf32_Ehdr))
        {
            throw std::runtime_error("File too small for ELF32 header");
        }
        auto *header = reinterpret_cast<const Elf32_Ehdr *>(file_content.data());
        parse_elf_header_32(header, info.get());
        parse_section_headers_32(header, info.get());
        parse_imports_32(info.get());
        parse_exports_32(info.get());
    }

    info->content = file_content;

    return info;
}

/*
HEADER
*/
void ElfParser::parse_elf_header_64(const Elf64_Ehdr *header, ElfInfo *info)
{
    switch (header->e_type)
    {
    case ET_NONE:
        info->file_type = "None";
        break;
    case ET_REL:
        info->file_type = "Relocatable";
        break;
    case ET_EXEC:
        info->file_type = "Executable";
        break;
    case ET_DYN:
        info->file_type = "Shared Object";
        break;
    case ET_CORE:
        info->file_type = "Core";
        break;
    default:
        info->file_type = "Unknown";
        break;
    }

    switch (header->e_machine)
    {
    case EM_ARM:
        info->architecture = "ARM";
        break;
    case EM_AARCH64:
        info->architecture = "AArch64";
        break;
    default:
        info->architecture = "Unknown";
        throw std::runtime_error("Can't parse this file format (yet)");
        break;
    }

    info->va = header->e_entry;
}

void ElfParser::parse_elf_header_32(const Elf32_Ehdr *header, ElfInfo *info)
{
    switch (header->e_type)
    {
    case ET_NONE:
        info->file_type = "None";
        break;
    case ET_REL:
        info->file_type = "Relocatable";
        break;
    case ET_EXEC:
        info->file_type = "Executable";
        break;
    case ET_DYN:
        info->file_type = "Shared Object";
        break;
    case ET_CORE:
        info->file_type = "Core";
        break;
    default:
        info->file_type = "Unknown";
        break;
    }

    switch (header->e_machine)
    {
    case EM_ARM:
        info->architecture = "ARM";
        break;
    case EM_AARCH64:
        info->architecture = "AArch64";
        break;
    default:
        info->architecture = "Unknown";
        throw std::runtime_error("Can't parse this file format (yet)");
        break;
    }

    info->va = header->e_entry;
}

/*
SECTIONS
*/
void ElfParser::parse_section_headers_64(const Elf64_Ehdr *header, ElfInfo *info)
{
    const char *strtab = nullptr;
    const auto *sections = reinterpret_cast<const Elf64_Shdr *>(file_content.data() + header->e_shoff);
    const auto &str_section = sections[header->e_shstrndx];

    strtab = reinterpret_cast<const char *>(file_content.data() + str_section.sh_offset);

    std::cerr << "Parsing sections. Total sections: " << header->e_shnum << std::endl;

    // parse all sections
    for (size_t i = 0; i < header->e_shnum; i++)
    {
        const auto &sec = sections[i];

        Section section;
        section.name = strtab + sec.sh_name;
        section.va = sec.sh_addr;
        section.size = sec.sh_size;
        section.flags = sec.sh_flags;
        section.offset = sec.sh_offset;

        if (section.flags & SHF_EXECINSTR || section.name == ".dynamic" || section.name == ".dynstr" || section.name == ".dynsym")
        {
            std::cerr << "  Copying section content for: " << section.name << std::endl;

            section.content.resize(section.size);
            std::memcpy(section.content.data(),
                        file_content.data() + section.offset,
                        section.size);

            std::cerr << "  Content size after copy: " << section.content.size() << std::endl;
        }

        if (section.name == ".dynstr" && !section.content.empty())
        {
            info->dynstr = reinterpret_cast<const char *>(section.content.data());
        }

        info->sections.push_back(std::move(section));
    }
}

void ElfParser::parse_section_headers_32(const Elf32_Ehdr *header, ElfInfo *info)
{
    const char *strtab = nullptr;
    const auto *sections = reinterpret_cast<const Elf32_Shdr *>(file_content.data() + header->e_shoff);
    const auto &str_section = sections[header->e_shstrndx];

    strtab = reinterpret_cast<const char *>(file_content.data() + str_section.sh_offset);

    std::cerr << "Parsing sections. Total sections: " << header->e_shnum << std::endl;

    // parse all sections
    for (size_t i = 0; i < header->e_shnum; i++)
    {
        const auto &sec = sections[i];
        std::cerr << "Section " << i << ": " << (strtab + sec.sh_name) << std::endl;
        std::cerr << "  Offset: 0x" << std::hex << sec.sh_offset << std::endl;
        std::cerr << "  Size: 0x" << sec.sh_size << std::dec << std::endl;
        std::cerr << "  Type: " << sec.sh_type << std::endl;

        Section section;
        section.name = strtab + sec.sh_name;
        section.va = sec.sh_addr;
        section.size = sec.sh_size;
        section.flags = sec.sh_flags;
        section.offset = sec.sh_offset;

        if (section.flags & SHF_EXECINSTR || section.name == ".dynamic" || section.name == ".dynstr" || section.name == ".dynsym")
        {
            std::cerr << "  Copying section content" << std::endl;

            section.content.resize(section.size);
            std::memcpy(section.content.data(),
                        file_content.data() + section.offset,
                        section.size);

            std::cerr << "  Content size after copy: " << section.content.size() << std::endl;
        }

        info->sections.push_back(std::move(section));
    }
}

/*
IMPORTS
*/
void ElfParser::parse_imports_64(ElfInfo *info)
{
    if (!info->dynstr)
        return;

    for (size_t i = 0; i < info->sections.size(); i++)
    {
        if (info->sections[i].name == ".dynamic" && !info->sections[i].content.empty())
        {
            auto *dyn = reinterpret_cast<Elf64_Dyn *>(info->sections[i].content.data());
            for (size_t j = 0; dyn[j].d_tag != DT_NULL; j++)
            {
                if (dyn[j].d_tag == DT_NEEDED)
                {
                    const char *str = info->dynstr + dyn[j].d_un.d_val;
                    std::string name(str);

                    if (!name.empty())
                    {
                        info->imports.push_back(std::move(name));
                    }
                }
            }
        }
    }
}

void ElfParser::parse_imports_32(ElfInfo *info)
{
    if (!info->dynstr)
        return;

    for (size_t i = 0; i < info->sections.size(); i++)
    {
        if (info->sections[i].name == ".dynamic" && !info->sections[i].content.empty())
        {
            auto *dyn = reinterpret_cast<Elf32_Dyn *>(info->sections[i].content.data());
            for (size_t j = 0; dyn[j].d_tag != DT_NULL; j++)
            {
                if (dyn[j].d_tag == DT_NEEDED)
                {
                    const char *str = info->dynstr + dyn[j].d_un.d_val;
                    std::string name(str);

                    if (!name.empty())
                    {
                        info->imports.push_back(std::move(name));
                    }
                }
            }
        }
    }
}

/*
EXPORTS
*/
void ElfParser::parse_exports_32(ElfInfo *info)
{
    if (!info->dynstr)
        return;

    for (size_t i = 0; i < info->sections.size(); i++)
    {
        if (info->sections[i].name == ".dynsym" && !info->sections[i].content.empty())
        {
            auto *sym = reinterpret_cast<Elf32_Sym *>(info->sections[i].content.data());
            size_t num_symbols = info->sections[i].size / sizeof(Elf32_Sym);

            for (size_t j = 0; j < num_symbols; j++)
            {
                uint8_t bind = ELF64_ST_BIND(sym[j].st_info);

                if ((bind == STB_GLOBAL || bind == STB_WEAK))
                {
                    std::string name(info->dynstr + sym[j].st_name);
                    info->exports.push_back(std::move(name));
                }
            }
        }
    }
}

void ElfParser::parse_exports_64(ElfInfo *info)
{
    if (!info->dynstr)
        return;

    for (size_t i = 0; i < info->sections.size(); i++)
    {
        if (info->sections[i].name == ".dynsym" && !info->sections[i].content.empty())
        {
            auto *sym = reinterpret_cast<Elf64_Sym *>(info->sections[i].content.data());
            size_t num_symbols = info->sections[i].size / sizeof(Elf64_Sym);

            for (size_t j = 0; j < num_symbols; j++)
            {
                uint8_t bind = ELF64_ST_BIND(sym[j].st_info);

                if ((bind == STB_GLOBAL || bind == STB_WEAK))
                {
                    std::string name(info->dynstr + sym[j].st_name);
                    info->exports.push_back(std::move(name));
                }
            }
        }
    }
}
