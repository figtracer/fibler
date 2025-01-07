#pragma once
#include <cstdint>

constexpr uint32_t ELF_MAGIC = 0x464C457F;

// e_ident indices
enum
{
    EI_MAG0 = 0,
    EI_MAG1 = 1,
    EI_MAG2 = 2,
    EI_MAG3 = 3,
    EI_CLASS = 4,
    EI_DATA = 5,
    EI_VERSION = 6,
    EI_OSABI = 7,
    EI_ABIVERSION = 8,
    EI_PAD = 9,
    EI_NIDENT = 16
};

enum
{
    ELFCLASS32 = 1,
    ELFCLASS64 = 2
};

enum
{
    ELFDATA2LSB = 1, // little
    ELFDATA2MSB = 2  // big
};

enum
{
    ET_NONE = 0,
    ET_REL = 1,
    ET_EXEC = 2,
    ET_DYN = 3,
    ET_CORE = 4
};

// architectures
enum
{
    EM_NONE = 0,     // No machine
    EM_386 = 3,      // Intel 80386
    EM_ARM = 40,     // ARM
    EM_X86_64 = 62,  // AMD x86-64
    EM_AARCH64 = 183 // ARM AARCH64
};

// 64-bit ELF header
struct Elf64_Ehdr
{
    uint8_t e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

// 32-bit ELF header
struct Elf32_Ehdr
{
    uint8_t e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry; // 32-bit address
    uint32_t e_phoff; // 32-bit offset
    uint32_t e_shoff; // 32-bit offset
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

// 64-bit ELF Section Header
struct Elf64_Shdr
{
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

// 32-bit ELF Section Header
struct Elf32_Shdr
{
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

// section executable flag
constexpr uint64_t SHF_EXECINSTR = 0x4;

struct Section
{
    std::string name;
    uint64_t va;
    uint64_t size;
    std::vector<uint8_t> content;
    uint64_t flags;
    uint64_t offset;
};

struct Elf32_Dyn
{
    int32_t d_tag; // Dynamic entry type
    union
    {
        uint32_t d_val; // Integer value
        uint32_t d_ptr; // Address value
    } d_un;
};

struct Elf64_Dyn
{
    int64_t d_tag; // Dynamic entry type
    union
    {
        uint64_t d_val; // Integer value
        uint64_t d_ptr; // Address value
    } d_un;
};

enum
{
    DT_NULL = 0,   // Marks end of dynamic section
    DT_NEEDED = 1, // Name of needed library
    DT_STRTAB = 5  // Address of string table
};

#define STB_LOCAL 0  // Local symbol
#define STB_GLOBAL 1 // Global symbol
#define STB_WEAK 2   // Weak symbol

// Symbol types
#define STT_NOTYPE 0  // Symbol type is unspecified
#define STT_OBJECT 1  // Symbol is a data object
#define STT_FUNC 2    // Symbol is a code object
#define STT_SECTION 3 // Symbol associated with a section
#define STT_FILE 4    // Symbol's name is file name

// Section types
#define SHT_NULL 0     // Section header table entry unused
#define SHT_PROGBITS 1 // Program data
#define SHT_SYMTAB 2   // Symbol table
#define SHT_STRTAB 3   // String table
#define SHT_RELA 4     // Relocation entries with addends
#define SHT_HASH 5     // Symbol hash table
#define SHT_DYNAMIC 6  // Dynamic linking information
#define SHT_NOTE 7     // Notes
#define SHT_NOBITS 8   // Program space with no data (bss)
#define SHT_REL 9      // Relocation entries, no addends
#define SHT_SHLIB 10   // Reserved
#define SHT_DYNSYM 11  // Dynamic linker symbol table

// Symbol table entry for ELF64
struct Elf64_Sym
{
    uint32_t st_name;  // Symbol name (string tbl index)
    uint8_t st_info;   // Symbol type and binding
    uint8_t st_other;  // Symbol visibility
    uint16_t st_shndx; // Section index
    uint64_t st_value; // Symbol value
    uint64_t st_size;  // Symbol size
};

// Symbol table entry for ELF32
struct Elf32_Sym
{
    uint32_t st_name;  // Symbol name (string tbl index)
    uint32_t st_value; // Symbol value
    uint32_t st_size;  // Symbol size
    uint8_t st_info;   // Symbol type and binding
    uint8_t st_other;  // Symbol visibility
    uint16_t st_shndx; // Section index
};

// Macros for manipulating st_info
#define ELF32_ST_BIND(val) ((val) >> 4)
#define ELF32_ST_TYPE(val) ((val) & 0xf)
#define ELF32_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))

#define ELF64_ST_BIND(val) ELF32_ST_BIND(val)
#define ELF64_ST_TYPE(val) ELF32_ST_TYPE(val)
#define ELF64_ST_INFO(bind, type) ELF32_ST_INFO((bind), (type))

#define SHN_UNDEF 0          // Undefined section
#define SHN_LORESERVE 0xff00 // Start of reserved indices
#define SHN_ABS 0xfff1       // Absolute values for reference
#define SHN_COMMON 0xfff2    // Common symbols
#define SHN_HIRESERVE 0xffff // End of reserved indices