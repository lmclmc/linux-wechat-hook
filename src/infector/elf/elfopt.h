#ifndef ELFOPT_H_
#define ELFOPT_H_

#include "elf_section.h"

#include <sys/stat.h>
#include <functional>

class Elf64SectionWrapper
{
    friend class Elf64Wrapper;
    using SecTab = std::map<std::string, std::shared_ptr<Elf64Section>>;
    typedef struct {
        //const Sym* dyn_sym;
        uint32_t nbuckets;
        uint32_t first_sym_ndx;
        uint32_t maskwords_bm;
        uint32_t shift2;
        uint64_t *bloom;
        uint32_t *buckets;
        uint32_t *hash_val;
    } GnuHashState;

public:
    Elf64SectionWrapper();
    ~Elf64SectionWrapper();
    SecTab &getSecTab();

    bool flush(const std::string &);

    bool editTab(std::function<bool(Elf64Section::SymTab &)>);

private:
    uint32_t elfHash(const char *);
    void calGnuHash(GnuHashState *obj_state, std::list<Symbol> &dynsymTab, 
                    uint32_t nbuckets, uint32_t ndx, 
                    uint32_t maskwords_bm, uint32_t shift2);
    void writeGnuHash(int fd, GnuHashState *obj_state, uint32_t defcount);
    void writeDynsym(int fd, Elf64_Addr baseAddr, std::list<Symbol> &dynsymTab);
    void writeDynStr(int fd, Elf64_Addr baseAddr, std::list<Symbol> &dynsymTab);
    void writeDynamicAndGnuver(int fd, Elf64_Addr dynstrAddr, 
                               Elf64_Addr gnuverAddr, Elf64_Addr dynamicAddr, 
                               std::list<GnuVer> &gnuverTab, 
                               std::list<Dynamic> dynamicTab);
    void updateRelasym(int fd, uint64_t relaBaseOffset, 
                       std::list<Symbol> &dynsymTab, int ndx);
private:
    SecTab mSecTab;
    uint8_t *pMmap;
    int mFd;
    struct stat mSt;
};

class Elf64Wrapper
{
public:
    Elf64Wrapper(){};
    ~Elf64Wrapper(){};

    bool loadSo(const std::string &, Elf64_Addr);

    Elf64_Addr getSymAddr(const std::string &, const std::string &);

    Elf64_Addr getSectionAddr(const std::string &, const std::string &);

    uint32_t getSectionSize(const std::string &, const std::string &);

    bool flush(const std::string &, const std::string &);

    bool editTab(const std::string &, std::function<bool(Elf64Section::SymTab &)>);

    void clearAllSyms();

private:
    std::map<std::string, std::shared_ptr<Elf64SectionWrapper>> mSecWrapperTab;
};
#endif