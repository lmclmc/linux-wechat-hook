#include "elf_dynsym.h"

#include <elf.h>

std::string Elf64DynsymSection::getSymbolBind(uint8_t &sym_bind) 
{
    switch(ELF32_ST_BIND(sym_bind)) {
        case 0: return "LOCAL";
        case 1: return "GLOBAL";
        case 2: return "WEAK";
        case 3: return "NUM";
        case 10: return "UNIQUE";
        case 12: return "HIOS";
        case 13: return "LOPROC";
        default: return "UNKNOWN";
    }
}

std::string Elf64DynsymSection::getSymbolVisibility(uint8_t &sym_vis)
{
    switch(ELF32_ST_VISIBILITY(sym_vis)) {
        case 0: return "DEFAULT";
        case 1: return "INTERNAL";
        case 2: return "HIDDEN";
        case 3: return "PROTECTED";
        default: return "UNKNOWN";
    }
}

std::string Elf64DynsymSection::getSymbolIndex(uint16_t &sym_idx) 
{
    switch(sym_idx) {
        case SHN_ABS: return "ABS";
        case SHN_COMMON: return "COM";
        case SHN_UNDEF: return "UND";
        case SHN_XINDEX: return "COM";
        default: return std::to_string(sym_idx);
    }
}

std::string Elf64DynsymSection::getSymbolType(uint8_t &sym_type) 
{
    switch(ELF32_ST_TYPE(sym_type)) {
        case 0: return "NOTYPE";
        case 1: return "OBJECT";
        case 2: return "FUNC";
        case 3: return "SECTION";
        case 4: return "FILE";
        case 6: return "TLS";
        case 7: return "NUM";
        case 10: return "LOOS";
        case 12: return "HIOS";
        default: return "UNKNOWN";
    }
}

void Elf64DynsymSection::pushSectionS(uint8_t *pMmap, 
                                      Section &section, 
                                      Elf64_Addr baseAddr,
                                      uint64_t userdata)
{
    auto total_syms = section.section_size / sizeof(Elf64_Sym);
    auto syms_data = (Elf64_Sym*)(pMmap + section.section_offset);
    char *pDynStr = (char *)pMmap + userdata;

    Symbol symbol;
    for (int i = 0; i < total_syms; ++i) {
        symbol.symbol_idx        = i;
        symbol.symbol_value      = syms_data[i].st_value + baseAddr;
        symbol.symbol_size       = syms_data[i].st_size;
        symbol.symbol_info       = syms_data[i].st_info;
        symbol.symbol_other       = syms_data[i].st_other;
        symbol.symbol_type       = getSymbolType(syms_data[i].st_info);
        symbol.symbol_bind       = getSymbolBind(syms_data[i].st_info);
        symbol.symbol_visibility = getSymbolVisibility(syms_data[i].st_other);
        symbol.symbol_index_str  = getSymbolIndex(syms_data[i].st_shndx);
        symbol.symbol_index      = syms_data[i].st_shndx;
        symbol.symbol_section    = section.section_name;  
        symbol.symbol_name_addr = syms_data[i].st_name;
        symbol.symbol_name = std::string(pDynStr + syms_data[i].st_name);
        symTab.emplace_back(symbol);
    }
}

Elf64_Addr Elf64DynsymSection::getSymAddr(const std::string &symname)
{
    for (auto &l : symTab)
    {
        if (l.symbol_name == symname)
            return l.symbol_value;
    }

    return 0;
}