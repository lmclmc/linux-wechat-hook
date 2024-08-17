#ifndef ELF_DYNSYM_H_
#define ELF_DYNSYM_H_

#include "elf_section.h"

class Elf64DynsymSection final: public Elf64Section
{
public:
    Elf64_Addr getSymAddr(const std::string &);

protected:
    void pushSectionS(uint8_t *, Section &, Elf64_Addr, uint64_t) override;

private:
    std::string getSymbolType(uint8_t &);
    std::string getSymbolBind(uint8_t &);
    std::string getSymbolVisibility(uint8_t &);
    std::string getSymbolIndex(uint16_t &); 
};

#endif