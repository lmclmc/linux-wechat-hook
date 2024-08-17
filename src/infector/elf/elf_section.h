#ifndef ELF_SECTION_H_
#define ELF_SECTION_H_

#include <list>
#include <iostream>
#include <map>
#include <memory>
#include <elf.h>

typedef struct {
    int section_index = 0; 
    std::intptr_t section_offset, section_addr;
    std::string section_name;
    int section_type; 
    int section_size, section_ent_size, section_addr_align;
} Section;

typedef struct {
    uint16_t symbol_index = 0;
    std::string symbol_index_str = "";
    std::intptr_t symbol_value = 0;
    uint32_t symbol_idx = 0, symbol_size = 0;
    unsigned char symbol_info = 0, symbol_other = 0;
    std::string symbol_type = "", symbol_bind = "";
    std::string symbol_visibility = "";
    uint64_t symbol_name_addr = 0;
    std::string symbol_name = "";
    std::string symbol_section = "";  
    std::map<int32_t, Elf64_Rela>  symbol_rela_table;
} Symbol;

typedef struct {
    bool need;
    uint32_t offset;
    std::string name;
    uint64_t gnuver[2];
} GnuVer;

typedef struct {
    Elf64_Dyn dyn;
    uint32_t offset;
    std::string name;
    uint32_t flag;
} Dynamic;

class Elf64Section
{
    friend class Elf64Wrapper;
    friend class Elf64SectionWrapper;
    using SymTab = std::list<Symbol>;
    using GnuVerTab = std::list<GnuVer>;
    using DynamicTab = std::list<Dynamic>;
public:
    void pushSection(uint8_t *pMap, Section &section, 
                     Elf64_Addr baseAddr, uint64_t userdata = 0)
    {
        sectionSize = section.section_size;
        sectionAddr = section.section_offset;
        pushSectionS(pMap, section, baseAddr, userdata);
    }

    Elf64_Addr getSectionAddr();

    uint32_t getSectionSize();

    SymTab &getSymTab();

    GnuVerTab &getGnuVerTab();

    DynamicTab &getDynamicTab();

protected:
    virtual void pushSectionS(uint8_t *, Section &section, 
                              Elf64_Addr, uint64_t){}

protected:
    uint32_t sectionSize;
    Elf64_Addr sectionAddr;
    static SymTab symTab;
    static GnuVerTab gnuVersionTab;
    static DynamicTab dynamicTab;
};

#endif