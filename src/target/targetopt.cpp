#include "targetopt.h"
#include "log/log.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAPS_PATH_LEN 64
#define LINE_LEN 512

TargetOpt::TargetOpt(int pid_) :
    pid(pid_),
    isAttach(false),
    TargetMaps(pid_)
{}

bool TargetOpt::attachTarget()
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) 
    {
        LOGGER_ERROR << "PTRACE_ATTACH: " << strerror(errno);
        return false;
    }
 
    isAttach = true;

    waitpid(pid, NULL, 0); 
    return true;
}

bool TargetOpt::detechTarget()
{
    if (!isAttach)
    {
        LOGGER_DEBUG << "target process isn't attach";
        return false;
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
    {
        LOGGER_ERROR << "PTRACE_DETACH: " << strerror(errno);
        return false;
    }

    return true;
}

bool TargetOpt::readTarget(unsigned long addr, void *vptr, int len)
{
    if (!isAttach)
    {
        LOGGER_WARNING << "target process isn't attach";
        return false;
    }

    int i,count;
    long word;
    long *ptr = (long *)vptr;
    i = count = 0;
    while (count < len) 
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
        while(word < 0)
        {
            if(errno == 0)
                break;

            LOGGER_ERROR << "PTRACE_PEEKTEXT: " << strerror(errno);
            return false;
        }
        count += 8;
        ptr[i++] = word;
    }
    return true;
}

bool TargetOpt::writeTarget(unsigned long addr, const void *vptr, int len)
{
    if (!isAttach)
    {
        LOGGER_WARNING << "target process isn't attach";
        return false;
    }

    int count;
    long word;

    count = 0;

    while (count < len) 
    {
        memcpy(&word, (const unsigned char *)vptr + count, sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
        count += 8;

        if(errno != 0)
        {
            LOGGER_ERROR << "PTRACE_POKETEXT: " << strerror(errno);
            return false;
        }
    }
    return true;
}

bool TargetOpt::readTarget(struct user_regs_struct &regs)
{ 
    if (!isAttach)
    {
        LOGGER_WARNING << "target process isn't attach";
        return false;
    }

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
    {
        LOGGER_ERROR << "PTRACE_GETREGS: " << strerror(errno);
        return false;
    }

    return true;
}

bool TargetOpt::writeTarget(struct user_regs_struct &regs)
{
    if (!isAttach)
    {
        LOGGER_WARNING << "target process isn't attach";
        return false;
    }

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
    {
        LOGGER_ERROR << "PTRACE_SETREGS: " << strerror(errno);
        return false;
    }

    return true;
}

bool TargetOpt::contTarget()
{
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
    {
        LOGGER_ERROR << "PTRACE_CONT: " << strerror(errno);
        return false;
    }

    return true;
}

bool TargetOpt::stepTarget()
{
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
    {
        LOGGER_ERROR << "PTRACE_SINGLESTEP: " << strerror(errno);
        return false;
    }

    int status;

	if (waitpid(pid, &status, 0) < 1)
    {
		LOGGER_ERROR << " waitpid " << strerror(errno);
		return false;
	}

	if (status)
    {
		if (WIFEXITED(status))
        {
			errno = ECHILD;
            LOGGER_ERROR << "pid = " << pid << "WIFEXITED = " << status;
			return false;
		}
		if (WIFSIGNALED(status))
        {
			errno = ECHILD;
            LOGGER_ERROR << "pidof = " << pid << " WIFSIGNALED = " << status 
                         << "WTERMSIG = " << status << " " << WTERMSIG(status);
			return false;
		}
		if (WIFCONTINUED(status))
        {
			errno = EINTR;
            LOGGER_ERROR << "pidof = " << pid << " WIFCONTINUED = " << status;
			return false;
		}
	}
    return true;
}

TargetMaps::TargetMaps(int pid_) :
    pid(pid_)
{}

std::map<std::string, uint64_t> &TargetMaps::getMapInfo()
{
    return mapInfos;
}

void TargetMaps::clearMapInfos()
{
    mapInfos.clear();
}

bool TargetMaps::readTargetAllMaps()
{
    if (mapInfos.size() > 0)
        return true;
        
    char mapsPath[MAPS_PATH_LEN];
    char line[LINE_LEN], tmp[32];
    char *p, *start;
    int i, size;
    std::string soAbsPath;
    Elf64_Addr baseAddr;
    
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", pid);
    FILE *fp;
    if ((fp = fopen(mapsPath, "r")) == NULL) 
    {
        LOGGER_ERROR << "fopen: " << strerror(errno);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) 
    {
        soAbsPath = "";

        for (i = 0, start = tmp, p = line; *p != '-'; i++, p++)
            start[i] = *p;

        start[i] = '\0';
        unsigned long long a1 = strtoull(start+4, NULL, 16);
        a1 &= 0xffffffff;
        start[4] = 0x0;
        unsigned long long a2 = strtoull(start, NULL, 16);
        baseAddr = (a2 << 32) + a1;

        p++;
        for (i = 0, start = tmp; *p != ' '; i++, p++)
            start[i] = *p;

        start[i] = '\0';
        a1 = strtoull(start+4, NULL, 16);
        a1 &= 0xffffffff;
        start[4] = 0x0;
        a2 = strtoull(start, NULL, 16);
        size =  (a2 << 32) + a1 - baseAddr;

        if (p = strchr(line, '/'))
        {
            *(char *)strchr(p, '\n') = '\0';
            soAbsPath = p;
        }
        if (p = strchr(line, '['))
        {
            *(char *)strchr(p, '\n') = '\0';
            soAbsPath = p;
        } 
        
        if (mapInfos.find(soAbsPath) != mapInfos.end())
            continue;
            
        mapInfos.insert({soAbsPath, baseAddr});
    }

    fclose(fp);
    return true;
}