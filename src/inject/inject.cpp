#include "inject.h"

#include <thread>

Inject *Inject::gInject = nullptr;
Elf64_Addr Inject::syscallTable[100] = {0};

Inject::Inject()
{
    gInject = this;
}

Inject::~Inject()
{}

void Inject::setAcceptAddr(Elf64_Addr addr_)
{
    syscallTable[SystemCall::ACCEPT] = addr_;
}

ssize_t Inject::injectAccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    Elf64_Addr funAddr = syscallTable[SystemCall::ACCEPT];

    if (gInject)
        gInject->evilAccept(sockfd, addr, addrlen);
 
    if (funAddr)
            return ((typeof(injectAccept) *)funAddr)(sockfd, addr, addrlen);

    return 0;
}

ssize_t Inject::injectRead(int fd, void *buf, size_t count)
{
    Elf64_Addr funAddr = syscallTable[SystemCall::READ];
    ssize_t ret = 0;

    if (funAddr)
        ret = ((typeof(injectRead) *)funAddr)(fd, buf, count);

    if (gInject)
        gInject->evilRead(fd, buf, count);

    return ret;
}

void Inject::setReadAddr(Elf64_Addr addr_)
{
    syscallTable[SystemCall::READ] = addr_;
}

ssize_t Inject::injectSend(int sockfd, const void *buf, size_t len, int flags)
{
    Elf64_Addr funAddr = syscallTable[SystemCall::SEND];

    if (gInject)
        gInject->evilSend(sockfd, buf, len, flags);

    if (funAddr)
        return ((typeof(injectSend) *)funAddr)(sockfd, buf, len, flags);
 
    return 0;
}

void Inject::setSendAddr(Elf64_Addr addr_)
{
    syscallTable[SystemCall::SEND] = addr_;
}

ssize_t Inject::injectWrite(int fd, const void *buf, size_t count)
{
    Elf64_Addr funAddr = syscallTable[SystemCall::WRITE];

    if (gInject)
        gInject->evilWrite(fd, buf, count);

    if (funAddr)
        return ((typeof(injectWrite) *)funAddr)(fd, buf, count);

    return 0;
}

void Inject::setWriteAddr(Elf64_Addr addr_)
{
    syscallTable[SystemCall::WRITE] = addr_;
}

int Inject::injectExecve(const char *pathname, char *const argv[],
                         char *const envp[])
{
    Elf64_Addr funAddr = syscallTable[SystemCall::EXECVE];

    if (gInject)
        gInject->evilExecve(pathname, argv, envp);

    if (funAddr)
        return ((typeof(injectExecve) *)funAddr)(pathname, argv, envp);

    return 0;
}

void Inject::setExecveAddr(Elf64_Addr addr_)
{
    syscallTable[SystemCall::EXECVE] = addr_;
}

pid_t Inject::injectFork()
{
    Elf64_Addr funAddr = syscallTable[SystemCall::FORK];
    int ret = 0;

    if (funAddr)
        ret = ((typeof(injectFork) *)funAddr)();

    if (gInject)
        gInject->evilFork(ret);

    return ret;
}

void Inject::setForkAddr(Elf64_Addr addr_)
{
    syscallTable[SystemCall::FORK] = addr_;
}