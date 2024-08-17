#ifndef ELF_DYNAMIC_H_
#define ELF_DYNAMIC_H_

#include "elf_section.h"

class Elf64DynamicSection final: public Elf64Section
{
protected:
    void pushSectionS(uint8_t *, Section &, Elf64_Addr, uint64_t) override;
};

#endif