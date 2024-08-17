#include "elf_dynamic.h"

void Elf64DynamicSection::pushSectionS(uint8_t *pMmap, 
                                       Section &section, 
                                       Elf64_Addr baseAddr,
                                       uint64_t userdata)
{
    auto total_dynamics = section.section_size / sizeof(Elf64_Dyn);
    auto dynamic_data = (Elf64_Dyn *)(pMmap + section.section_offset);
    char *pDynStr = (char *)pMmap + userdata;

    Dynamic dynamic;
    for (int i = 0; i < total_dynamics; ++i) {
        dynamic.dyn.d_tag = dynamic_data[i].d_tag;
        dynamic.dyn.d_un.d_ptr = dynamic_data[i].d_un.d_ptr;
        dynamic.offset = dynamic_data[i].d_un.d_ptr;
        dynamic.name = std::string(dynamic.offset + pDynStr);
        dynamic.flag = 0;
        dynamicTab.emplace_back(dynamic);
    }
}