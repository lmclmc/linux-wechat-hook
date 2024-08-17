#include "elf_reladyn.h"

void Elf64RelaDynSectoin::pushSectionS(uint8_t *pMmap, 
                                       Section &section, 
                                       Elf64_Addr baseAddr,
                                       uint64_t userdata)
{
    uint64_t relapltSize = userdata;
    auto total_syms = (section.section_size + relapltSize) / sizeof(Elf64_Rela);
    auto syms_data = (Elf64_Rela*)(pMmap + section.section_offset);
    for (int i = 0; i < total_syms; i++)
    {
        uint64_t idx = syms_data[i].r_info >> 32;
        for (auto &l : symTab)
        {
            if (l.symbol_idx == idx)
            {
                l.symbol_rela_table[i] = syms_data[i];
                break;
            }
        }
    }
}