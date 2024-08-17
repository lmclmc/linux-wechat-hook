#include "elf_section.h"

Elf64Section::SymTab Elf64Section::symTab;
Elf64Section::GnuVerTab Elf64Section::gnuVersionTab;
Elf64Section::DynamicTab Elf64Section::dynamicTab;

Elf64_Addr Elf64Section::getSectionAddr()
{
    return sectionAddr;
}

uint32_t Elf64Section::getSectionSize()
{
    return sectionSize;
}

Elf64Section::SymTab &Elf64Section::getSymTab()
{
    return symTab;
}

Elf64Section::GnuVerTab &Elf64Section::getGnuVerTab()
{
    return gnuVersionTab;
}

Elf64Section::DynamicTab &Elf64Section::getDynamicTab()
{
    return dynamicTab;
}