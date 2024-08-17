#ifndef ELF_GNUVER_R_H_
#define ELF_GNUVER_R_H_

#include "elf_section.h"

class Elf64GnuVerSectoin final : public Elf64Section
{
protected:
    void pushSectionS(uint8_t *, Section &, Elf64_Addr, uint64_t) override;
};

#endif