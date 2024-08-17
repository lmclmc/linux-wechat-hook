#include "elfopt.h"
#include "log/log.h"
#include "threadpool/workqueue.h"
#include "util/single.hpp"

#include "elf_dynsym.h"
#include "elf_reladyn.h"
#include "elf_gnuver_r.h"
#include "elf_dynamic.h"

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define SECTION_DYNSTR_STR ".dynstr"
#define SECTION_DYNSYM_STR ".dynsym"
#define SECTION_RELADYN_STR ".rela.dyn"
#define SECTION_RELAPLT_STR ".rela.plt"
#define SECTION_GNUVERSION_STR ".gnu.version_r"
#define SECTION_DYNAMIC_STR ".dynamic"

using namespace lmc;

Elf64SectionWrapper::Elf64SectionWrapper() : pMmap(nullptr),
                                             mFd(0)
{
    mSecTab[SECTION_DYNSYM_STR] = std::make_shared<Elf64DynsymSection>();
    mSecTab[SECTION_RELADYN_STR] = std::make_shared<Elf64RelaDynSectoin>();
    mSecTab[SECTION_GNUVERSION_STR] = std::make_shared<Elf64GnuVerSectoin>();
    mSecTab[SECTION_DYNAMIC_STR] = std::make_shared<Elf64DynamicSection>();
}

Elf64SectionWrapper::~Elf64SectionWrapper()
{
    mSecTab.clear();

    if (!(pMmap && munmap(pMmap, mSt.st_size) >= 0))
        LOGGER_ERROR << strerror(errno);

    if (!(mFd > 0 && close(mFd) > 0))
        LOGGER_ERROR << strerror(errno);
}

uint32_t Elf64SectionWrapper::elfHash(const char* name)
{
    if (!name)
        return 0;

    const unsigned char *n = (const unsigned char *)name;
    uint32_t h = 5381;
    for (unsigned char c = *n; c != '\0'; c = *++n)
            h = h*33 + c;

    return h;
}

void Elf64SectionWrapper::calGnuHash(GnuHashState *obj_state, 
                                     std::list<Symbol> &dynsymTab, 
                                     uint32_t nbuckets, uint32_t ndx, 
                                     uint32_t maskwords_bm, uint32_t shift2)
{
    obj_state->nbuckets = nbuckets;
    obj_state->first_sym_ndx = ndx;
    obj_state->maskwords_bm = maskwords_bm;
    obj_state->shift2 = shift2;
 
    obj_state->bloom = (uint64_t *)calloc(obj_state->maskwords_bm, sizeof(uint64_t));
    obj_state->buckets = (uint32_t *)calloc(obj_state->nbuckets, sizeof(uint32_t));
    obj_state->hash_val = (uint32_t *)calloc(dynsymTab.size(), sizeof(uint32_t));

    uint32_t c = sizeof(uint64_t) * 8;
    uint32_t countIdx = ndx;
    for (auto it = dynsymTab.begin(); it != dynsymTab.end(); it++)
    {
        uint32_t h1 = elfHash((const char *)it->symbol_name.c_str());
        uint32_t h2 = h1 >> obj_state->shift2;

        uint32_t n = (h1 / c) % obj_state->maskwords_bm;
        uint64_t bitmask = ((uint64_t)1 << (h1 % c)) | 
                           ((uint64_t)1 << (h2 % c));

        obj_state->bloom[n] |= bitmask;

        size_t bucket_idx = h1 % obj_state->nbuckets;
        n = obj_state->buckets[bucket_idx];
        if (n == 0)
            obj_state->buckets[bucket_idx] = countIdx;

        auto it_bk = it;
        uint32_t lsb = 0;
        if (++it_bk != dynsymTab.end())
        {
            uint32_t h11 = elfHash((const char *)
                           (it_bk)->symbol_name.c_str()) % obj_state->nbuckets;
            lsb = (h1 % obj_state->nbuckets) != h11;
        } else
        {
            lsb = 1;
        }

        uint32_t h_val = (h1 & ~1) | lsb;

        obj_state->hash_val[countIdx - ndx] = h_val;
        countIdx++;
    }
}

void Elf64SectionWrapper::writeGnuHash(int fd, GnuHashState *obj_state, 
                                       uint32_t defcount)
{
    size_t bloom_size = obj_state->maskwords_bm * sizeof(uint64_t);
    size_t bucket_size = obj_state->nbuckets * sizeof(uint32_t);
    size_t val_size = defcount * sizeof(uint32_t);
    size_t obj_size = 4 * 4 + bloom_size + bucket_size + val_size;

    unsigned char* pObj = (unsigned char*)obj_state;
    size_t p_chg_size = 16;
    for (size_t i = 0; i < obj_size; i++) {
        if (i == 16) {
            pObj = (unsigned char*)obj_state->bloom;
        } else if (i == 16 + bloom_size) {
            pObj = (unsigned char*)obj_state->buckets;
        } else if (i == 16 + bloom_size+bucket_size) {
            pObj = (unsigned char*)obj_state->hash_val;
        }

        write(fd, pObj++, 1);
    }
}

void Elf64SectionWrapper::writeDynsym(int fd, Elf64_Addr baseAddr,
                                      std::list<Symbol> &dynsymTab)
{
    lseek(fd, baseAddr, SEEK_SET);
    Elf64_Sym sym;
    for (auto &d : dynsymTab)
    {
        sym.st_name = d.symbol_name_addr;
        sym.st_info = d.symbol_info;
        sym.st_other = d.symbol_other;
        sym.st_shndx = d.symbol_index;
        sym.st_size = d.symbol_size;
        sym.st_value = d.symbol_value;
        
        write(fd, &sym, sizeof(Elf64_Sym));
    }
}

void Elf64SectionWrapper::writeDynStr(int fd, Elf64_Addr baseAddr,
                                      std::list<Symbol> &dynsymTab)
{
    Elf64_Sym sym;
    for (auto &d : dynsymTab)
    {
        lseek(fd, baseAddr + d.symbol_name_addr, SEEK_SET);
        write(fd, d.symbol_name.c_str(), d.symbol_name.size());
        write(fd, "\0", 1);
    }
}

void Elf64SectionWrapper::writeDynamicAndGnuver(int fd, Elf64_Addr dynstrAddr, 
                                                Elf64_Addr gnuverAddr, 
                                                Elf64_Addr dynamicAddr, 
                                                std::list<GnuVer> &gnuverTab, 
                                                std::list<Dynamic> dynamicTab)
{
    for (auto &g : gnuverTab)
    {
        lseek(fd, dynstrAddr + g.offset, SEEK_SET);
        write(fd, g.name.c_str(), g.name.size());
        write(fd, "\0", 1);
        for (auto &d : dynamicTab)
        {
            if (d.dyn.d_tag == DT_NEEDED && g.name == d.name)
            {
                d.dyn.d_un.d_ptr = g.offset;
                d.flag = 1;
            }
        }
    }

    for (auto &d : dynamicTab)
    {
        if ((d.dyn.d_tag == DT_NEEDED && !d.flag) || d.dyn.d_tag == DT_SONAME)
        {
            d.dyn.d_un.d_ptr = lseek(fd, 0, SEEK_CUR) - dynstrAddr;
            write(fd, d.name.c_str(), d.name.size());
            write(fd, "\0", 1);
        }
    }

    lseek(fd, gnuverAddr, SEEK_SET);
    for (auto &g : gnuverTab)
    {
        write(fd, &g.gnuver, sizeof(GnuVer::gnuver));
    }

    lseek(fd, dynamicAddr, SEEK_SET);
    for (auto &d : dynamicTab)
    {
        write(fd, &d.dyn, sizeof(Elf64_Dyn));
    }
}

void Elf64SectionWrapper::updateRelasym(int fd, uint64_t relaBaseOffset, 
                                        std::list<Symbol> &dynsymTab, int ndx)
{
    uint64_t idx = ndx;
    int count = 0;
    for (auto &d : dynsymTab)
    {
        for (auto &m : d.symbol_rela_table)
        {
            m.second.r_info =  (idx << 32) | (m.second.r_info & 0xffffffff);
            lseek(fd, relaBaseOffset + sizeof(Elf64_Rela) * m.first, SEEK_SET);
            write(fd, &m.second, sizeof(Elf64_Rela));
        }

        idx++;
    }
}

bool Elf64SectionWrapper::editTab(std::function<bool(Elf64Section::SymTab &)> cb)
{
    return cb(mSecTab.begin()->second->getSymTab());
}

bool Elf64SectionWrapper::flush(const std::string &output_soname)
{
    int mOutputFd = 0;
    if ((mOutputFd = open(output_soname.c_str(), O_CREAT | O_RDWR)) < 0)
    {
        LOGGER_ERROR << "open: " << output_soname << strerror(errno);
        return false;
    }

    write(mOutputFd, pMmap, mSt.st_size);

    std::list<Symbol> dynUndefSymTab;
    auto &dynsymTab = mSecTab.begin()->second->getSymTab();
    auto &gnuverTab = mSecTab.begin()->second->getGnuVerTab();
    auto &dynamicTab = mSecTab.begin()->second->getDynamicTab();
    
    uint64_t addrcount = 0;
    for (auto it = dynsymTab.begin();;)
    {
        if (it->symbol_name.empty() || it->symbol_index == SHN_UNDEF)
        {
            it->symbol_name_addr = addrcount;
            addrcount = addrcount + it->symbol_name.size() + 1;
            dynUndefSymTab.emplace_back(*it);
            it = dynsymTab.erase(it);
        } else 
        {
            it++;
            if (it == dynsymTab.end())
                break;

            it->symbol_name_addr = addrcount;
            addrcount = addrcount + it->symbol_name.size() + 1;
        }
    }

    for (auto &g : gnuverTab)
    {
        if (g.need)
        {
            ((Elf64_Verneed *)&g.gnuver)->vn_file = addrcount;
        } else {
            ((Elf64_Vernaux *)&g.gnuver)->vna_name = addrcount;
        }
        g.offset = addrcount;
        addrcount = addrcount + g.name.size() + 1;
    }

    Elf64_Addr gnuhashAddr = mSecTab[".gnu.hash"]->getSectionAddr();
    if (!gnuhashAddr)
    {
        LOGGER_ERROR << "gnu hash section not exist";
        return false;
    }

    Elf64_Addr gnuhashMapAddr = (Elf64_Addr)pMmap + gnuhashAddr;
    uint32_t nbuckets = *(Elf64_Addr *)gnuhashMapAddr & 0xffffffff;
    uint32_t undefCount = *(Elf64_Addr *)gnuhashMapAddr >> 32;
    uint32_t maskwords_bm = *((Elf64_Addr *)gnuhashMapAddr+1) & 0xffffffff;
    uint32_t shift2 = *((Elf64_Addr *)gnuhashMapAddr+1) >> 32;
    dynsymTab.sort([=](const Symbol &s1, const Symbol &s2){
        uint32_t sh1 = elfHash((const char *)s1.symbol_name.c_str()) % nbuckets;
        uint32_t sh2 = elfHash((const char *)s2.symbol_name.c_str()) % nbuckets;
        return sh1 < sh2;
    });

    GnuHashState obj_state;
    calGnuHash(&obj_state, dynsymTab, nbuckets, undefCount, 
               maskwords_bm, shift2);
    lseek(mOutputFd, gnuhashAddr, SEEK_SET);
    writeGnuHash(mOutputFd, &obj_state, dynsymTab.size());

    Elf64_Addr dynsymAddr = mSecTab[".dynsym"]->getSectionAddr();
    writeDynsym(mOutputFd, dynsymAddr, dynUndefSymTab);
    writeDynsym(mOutputFd, dynsymAddr + dynUndefSymTab.size() * 0x18, dynsymTab);

    Elf64_Addr dynstrAddr = mSecTab[".dynstr"]->getSectionAddr();
    uint32_t dynstrSize = mSecTab[".dynstr"]->getSectionSize();
    unsigned char buffer[1024 * 1024] = {0};
    lseek(mOutputFd, dynstrAddr, SEEK_SET);
    write(mOutputFd, buffer, dynstrSize);

    writeDynStr(mOutputFd, dynstrAddr, dynUndefSymTab);
    writeDynStr(mOutputFd, dynstrAddr, dynsymTab);

    Elf64_Addr dynamicAddr = mSecTab[".dynamic"]->getSectionAddr();
    Elf64_Addr gnuverAddr = mSecTab[".gnu.version_r"]->getSectionAddr();
    writeDynamicAndGnuver(mOutputFd, dynstrAddr, gnuverAddr, 
                          dynamicAddr, gnuverTab, dynamicTab);
    
    Elf64_Addr reladynAddr = mSecTab[".rela.dyn"]->getSectionAddr();
    updateRelasym(mOutputFd, reladynAddr, dynsymTab, undefCount);

    close(mOutputFd);
    return true;
}

Elf64SectionWrapper::SecTab &Elf64SectionWrapper::getSecTab()
{
    return mSecTab;
}

uint32_t Elf64Wrapper::getSectionSize(const std::string &soname, 
                                      const std::string &sectionName)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        auto &pSecTab = pSecWrapper->getSecTab();
        if (pSecTab.find(sectionName) != pSecTab.end())
        {
            return pSecTab[sectionName]->getSectionSize();
        }
    }
    return 0;
}

Elf64_Addr Elf64Wrapper::getSectionAddr(const std::string &soname, 
                                        const std::string &sectionName)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        auto &pSecTab = pSecWrapper->getSecTab();
        if (pSecTab.find(sectionName) != pSecTab.end())
        {
            return pSecTab[sectionName]->getSectionAddr();
        }
    }
    return 0;
}

bool Elf64Wrapper::loadSo(const std::string &soname, Elf64_Addr baseAddr)
{
    int fd;
    unsigned char *pMmap;
    struct stat st; 
    if ((fd = open(soname.c_str(), O_RDONLY)) < 0) 
    {
        LOGGER_ERROR << "open: " << soname << strerror(errno);
        return false;
    }

    if (fstat(fd, &st) < 0) 
    {
        LOGGER_ERROR << "fstat: " << strerror(errno);
        return false;
    }

    pMmap = static_cast<uint8_t*>(mmap(NULL, st.st_size, PROT_READ, 
                                       MAP_PRIVATE, fd, 0));
    if (pMmap == MAP_FAILED) 
    {
        LOGGER_ERROR << "mmap: " << strerror(errno);
        return false;
    }

    auto eHdr = (Elf64_Ehdr *)pMmap;
    if (eHdr->e_ident[EI_CLASS] != ELFCLASS64) 
    {
        LOGGER_ERROR << "Only 64-bit files supported";
        return false;
    }

    if (!mSecWrapperTab[soname])
        mSecWrapperTab[soname] = std::make_shared<Elf64SectionWrapper>();

    auto pSecWrapper = mSecWrapperTab[soname];
    pSecWrapper->mFd = fd;
    pSecWrapper->pMmap = pMmap;
    pSecWrapper->mSt = st;

    auto &pSecTable = pSecWrapper->getSecTab();

    Elf64_Shdr *sHdr = (Elf64_Shdr*)(pMmap + eHdr->e_shoff);
    int shnum = eHdr->e_shnum;

    Elf64_Shdr *sStrtab = &sHdr[eHdr->e_shstrndx];
    const char *const pStrtab = (char *)pMmap + sStrtab->sh_offset;

    WorkQueue *work = TypeSingle<WorkQueue>::getInstance(MutexType::None);
    std::future<bool> dynsymFuture;
    std::future<bool> reladynFuture;
    std::future<bool> gnuversoinFuture;
    std::future<bool> dynamicFuture;

    std::promise<uint64_t> dynstrPromise;
    std::shared_future<uint64_t> dynstrFuture = 
                                 dynstrPromise.get_future().share();

    std::promise<uint64_t> relapltPromise;
    std::future<uint64_t> relapltFuture = relapltPromise.get_future();
    
    for (int i = 0; i < shnum; ++i) 
    {
        Section section;
        section.section_index = i;
        section.section_name = std::string(pStrtab + sHdr[i].sh_name);
        section.section_type = sHdr[i].sh_type;
        section.section_addr = sHdr[i].sh_addr;
        section.section_offset = sHdr[i].sh_offset;
        section.section_size = sHdr[i].sh_size;
        section.section_ent_size = sHdr[i].sh_entsize;
        section.section_addr_align = sHdr[i].sh_addralign;
        if (!pSecTable[section.section_name])
        {
            pSecTable[section.section_name] = std::make_shared<Elf64Section>();
        }

        if (section.section_name == SECTION_DYNSTR_STR)
        {
            dynstrPromise.set_value(section.section_offset);
        } else if (section.section_name == SECTION_DYNSYM_STR)
        {
            dynsymFuture = work->addTask([&](uint8_t *pMap, 
                                             Section &section, 
                                             Elf64_Addr baseAddr){
                uint64_t offset = dynstrFuture.get();
                pSecTable[section.section_name]->pushSection(pMmap,
                                                             section,
                                                             baseAddr,
                                                             offset);
                return true;
            }, pMmap, section, baseAddr);
            continue;
        } else if (section.section_name == SECTION_RELADYN_STR)
        {
            reladynFuture = work->addTask([&](uint8_t *pMap, 
                                              Section &section, 
                                              Elf64_Addr baseAddr){
                uint64_t size = relapltFuture.get();
                pSecTable[section.section_name]->pushSection(pMmap,
                                                             section,
                                                             baseAddr,
                                                             size);
                return true;
            }, pMmap, section, baseAddr);
            continue;
        } else if (section.section_name == SECTION_RELAPLT_STR)
        {
            relapltPromise.set_value(section.section_size);
        } else if (section.section_name == SECTION_GNUVERSION_STR)
        {
            gnuversoinFuture = work->addTask([&](uint8_t *pMap, 
                                                 Section &section, 
                                                 Elf64_Addr baseAddr){
                uint64_t offset = dynstrFuture.get();
                pSecTable[section.section_name]->pushSection(pMmap,
                                                             section,
                                                             baseAddr,
                                                             offset);
                return true;
            }, pMmap, section, baseAddr);
            continue;
        } else if (section.section_name == SECTION_DYNAMIC_STR)
        {
            dynamicFuture = work->addTask([&](uint8_t *pMap, 
                                              Section &section, 
                                              Elf64_Addr baseAddr){
                uint64_t offset = dynstrFuture.get();
                pSecTable[section.section_name]->pushSection(pMmap,
                                                             section,
                                                             baseAddr,
                                                             offset);
                return true;
            }, pMmap, section, baseAddr);
            continue;
        }

        pSecTable[section.section_name]->pushSection(pMmap, 
                                                     section, 
                                                     baseAddr);
    }

    dynamicFuture.get();
    dynsymFuture.get();
    reladynFuture.get();
    gnuversoinFuture.get();

    return true;
}

Elf64_Addr Elf64Wrapper::getSymAddr(const std::string &soname, 
                                    const std::string &symname)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        auto pDynSymSec = std::dynamic_pointer_cast<Elf64DynsymSection>(
                               pSecWrapper->getSecTab()[SECTION_DYNSYM_STR]);
        if (pDynSymSec)
        {
            return pDynSymSec->getSymAddr(symname);
        }
    }

    return 0;
}

void Elf64Wrapper::clearAllSyms()
{
    mSecWrapperTab.clear();
}

bool Elf64Wrapper::flush(const std::string &soname, 
                         const std::string &output_soname)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        return pSecWrapper->flush(output_soname);
    }

    return false;
}

bool Elf64Wrapper::editTab(const std::string &soname, 
                           std::function<bool(Elf64Section::SymTab &)> cb)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
        return pSecWrapper->editTab(cb);

    return false;
}