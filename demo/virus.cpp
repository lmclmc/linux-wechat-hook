#include "version.h"

#include "infector/infector.h"
#include "cmdline/cmdline.h"
#include "util/single.hpp"
#include "log/log.h"
#include "infector/editso.h"

#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>

#define LIBC_SO "libc-2.31.so"

using namespace lmc;

int main(int argc, char *argv[])
{
    CmdLine *pCmd = TypeSingle<CmdLine>::getInstance();
    pCmd->add<int>("-p", "--pid", "set target pid", {}, {1, 1000000});
    pCmd->add<std::list<std::string>>("-l", "--link", "link so", {"--pid"});
    pCmd->add<std::string>("-ga", "--getfunaddr", 
                           "get target process function addr", {"--pid"});
    pCmd->add<std::string>("-sl", "--setloglevel", "set log level", {},
                          {"info", "error", "debug", "warning", "all"});
    pCmd->add<std::string>("-o", "--outputfile", "set output log file");
    pCmd->add<std::string>("-sa", "--setaddr", 
                           "set target mem addr", {"--pid"});
    pCmd->add<std::string>("-w", "--write", "write str to target mem", 
                          {"--pid", "--setaddr"});
    pCmd->add<int>("-r", "--read", "read str from target mem", 
                  {"--pid", "--setaddr"});
    pCmd->add("-ho", "--hook", "hook syscall", {"--pid", "--link"});
    pCmd->add<std::string>("-od", "--old_dynsymstr", "input old dynsym name");
    pCmd->add<std::string>("-nd", "--new_dynsymstr", "input new dynsym name", {"-od"});
    pCmd->add<std::string>("-so", "--soname", "input so name");
    pCmd->add<std::string>("-ou", "--output_so", "output so name", {"-so"});
    pCmd->add("-c", "--confuse", "symbols confuse", {"-so", "-ou"});
    pCmd->add<std::set<std::string>>("-sf", "--strfilter", "symbols filter", {"-c"});
    pCmd->add("-v", "--version", "get version");

    pCmd->parse(false, argc, argv);

    bool ret = pCmd->get("--version");
    if (ret)
    {
        std::cout << "version: " << PROJECT_VERSION << std::endl;
        exit(0);
    }
    
    Logger::setLevel(LogLevel::all);
    std::string logStr;
    ret = pCmd->get("--setloglevel", logStr);
    if (ret && !logStr.empty())
    {
        if (logStr == "close")
            Logger::setLevel(LogLevel::close);
        else if (logStr == "info")
            Logger::setLevel(LogLevel::info);
        else if (logStr == "warning")
            Logger::setLevel(LogLevel::warning);
        else if (logStr == "debug")
            Logger::setLevel(LogLevel::debug);
        else if (logStr == "error")
            Logger::setLevel(LogLevel::error);
        else if (logStr == "all")
            Logger::setLevel(LogLevel::all);
    }

    std::string old_dynsymStr = "";
    std::string new_dynsymStr = "";
    std::string input_soname = "";
    std::string output_soname = "";
    if (pCmd->get("-so", input_soname) &&
        pCmd->get("-ou", output_soname) &&
        pCmd->get("-od", old_dynsymStr) &&
        pCmd->get("-nd", new_dynsymStr))
    {
        EditSo editSo;
        editSo.replaceSoDynsym(old_dynsymStr,
                               new_dynsymStr,
                               input_soname,
                               output_soname);
        return 0;
    }
    
    if (pCmd->get("-c"))
    {
        EditSo editSo;
        std::set<std::string> filterstr;
        pCmd->get("-sf", filterstr);
        editSo.confuse(input_soname, output_soname, filterstr);
        return 0;
    }

    std::string outputfileStr;
    ret = pCmd->get("--outputfile", outputfileStr);
    if (ret && !outputfileStr.empty())
        Logger::setOutputFile(outputfileStr);
    
    int pid;
    ret = pCmd->get("--pid", pid);
    if (!ret)
    {
        LOGGER_INFO << "please set --pid";
        return 0;
    }
 
    std::string addrStr;
    Infector infector(pid, LIBC_SO);
    ret = pCmd->get("--setaddr", addrStr);
    if (ret && !addrStr.empty())
    {
        Elf64_Addr targetAddr;
        sscanf(addrStr.c_str(), "%lx", &targetAddr);
        LOGGER << LogFormat::addr << "targetAddr = " << targetAddr;
        infector.attachTarget();

        std::string writeStr;
        ret = pCmd->get("--write", writeStr);
        if (ret && !writeStr.empty())
        {
            if (infector.writeStrToTarget(targetAddr, writeStr))
            {
                LOGGER << "write " << writeStr << " successful";
            }
            else
            {
                LOGGER << "write " << writeStr << " failed";
            }
        }

        int readSize = 0;
        ret = pCmd->get("--read", readSize);
        if (ret)
        {
            std::string str;
            if (infector.readStrFromTarget(targetAddr, str, readSize))
            {
                LOGGER << "read " << str << " successful";
            }
            else
            {
                LOGGER << "read " << str << " failed";
            }
        }
    }

    std::string funaddrStr;
    ret = pCmd->get("--getfunaddr", funaddrStr);
    if (ret)
    {
        infector.loadAllSoFile();
        LOGGER << LogFormat::addr << infector.getSymAddr(funaddrStr);
        return 0;
    }

    std::list<std::string> linkList;
    ret = pCmd->get("--link", linkList);
    if (ret && linkList.size())
    {
        if (!infector.attachTarget())
        {
            LOGGER_ERROR << "attachTarget";
            return 0;
        }

        for (auto &l : linkList)
        {
            infector.injectEvilSoname(l);
        }
    }
    
    ret = pCmd->get("--hook");
    if (ret)
    {
        infector.injectSysTableInit();
    }

    if (!infector.detachTarget())
    {
        return 0;
    }
}