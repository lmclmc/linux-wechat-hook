#include "editso.h"
#include "elf/elfopt.h"
#include "util/single.hpp"
#include "log/log.h"

#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

using namespace lmc;

static std::string randStr()
{
    static int count = 0;
    return std::to_string(count++);
}

bool EditSo::confuse(const std::string &input_soname,
                     const std::string &output_soname,
                     const std::set<std::string> &filter)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    if (!pElf->loadSo(input_soname, 0))
    {
        LOGGER_ERROR << " open " << input_soname << " error";
        return false;
    }
  
    pElf->editTab(input_soname, [&](std::list<Symbol> &symTab) -> bool {
        for (auto &s : symTab) {
            if (s.symbol_name.empty() || s.symbol_index == SHN_UNDEF || 
                filter.find(s.symbol_name) != filter.end())
                continue;

            s.symbol_name = randStr();
        }

        return true;
    });

    return pElf->flush(input_soname, output_soname);
}

bool EditSo::replaceSoDynsym(const std::string &old_name,
                             const std::string &new_name,
                             const std::string &input_soname,
                             const std::string &output_soname)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    if (!pElf->loadSo(input_soname, 0))
    {
        LOGGER_ERROR << " open " << input_soname << " error";
        return false;
    }
  
    if (!pElf->editTab(input_soname, [&](std::list<Symbol> &symTab) -> bool {
        for (auto &s : symTab) {
            if (s.symbol_name == old_name)
            {
                s.symbol_name = new_name;
                return true;
            }
        }

        return false;
    }))
    {
        LOGGER_ERROR << old_name << " not found";
        return false;
    }

    if (!pElf->flush(input_soname, output_soname))
    {
        LOGGER_ERROR << " flush " << " error";
        return false;
    }

    return true;
}