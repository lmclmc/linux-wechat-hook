#include "elf_gnuver_r.h"

#include "string.h"

void Elf64GnuVerSectoin::pushSectionS(uint8_t *pMmap, 
                                      Section &section, 
                                      Elf64_Addr baseAddr,
                                      uint64_t userdata)
{
    auto total_gnu_versions = section.section_size / sizeof(GnuVer::gnuver);
    auto gnuversion_data = (decltype(GnuVer::gnuver) *)(pMmap + 
                                                        section.section_offset);
    char *pDynStr = (char *)pMmap + userdata;

    GnuVer gnuver;
    for (int i = 0; i < total_gnu_versions; ++i) {
        if ((*(unsigned short*)&gnuversion_data[i]) == 0x1)
        {
            gnuver.need = true;
            gnuver.offset = (*(Elf64_Verneed *)&gnuversion_data[i]).vn_file;
        } else {
            gnuver.need = false;
            gnuver.offset = (*(Elf64_Vernaux *)&gnuversion_data[i]).vna_name;
        }
        gnuver.name = std::string(pDynStr +gnuver.offset);

        memcpy(&gnuver.gnuver, &gnuversion_data[i],sizeof(GnuVer::gnuver));
        gnuVersionTab.emplace_back(gnuver);
    }
}