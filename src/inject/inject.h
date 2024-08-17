#ifndef INJECT_H_
#define INJECT_H_

#include <stdio.h>
#include <elf.h>
#include <sys/socket.h>

#define EXPORT_INJECT(type) \
    type g##type;

typedef enum classSystemCall_ : unsigned char
{
    ACCEPT = 0,
    READ = 1,
    SEND = 2,
    WRITE = 3,
    EXECVE = 4,
    FORK = 5
}SystemCall;

class Inject
{
public:
    Inject();
    virtual ~Inject();

protected:
    virtual ssize_t evilAccept(int, struct sockaddr *, socklen_t *) = 0;
    virtual ssize_t evilRead(int, void *, size_t) = 0;
    virtual ssize_t evilSend(int, const void *, size_t, int) = 0;
    virtual ssize_t evilWrite(int, const void *, size_t) = 0;
    virtual int evilExecve(const char *, char *const [], char *const []) = 0;
    virtual pid_t evilFork(pid_t) = 0;
    virtual void evilMain() = 0;

private:
    static ssize_t injectAccept(int, struct sockaddr *, socklen_t *);
    void setAcceptAddr(Elf64_Addr);

    static ssize_t injectRead(int, void *, size_t); 
    void setReadAddr(Elf64_Addr);

    static ssize_t injectSend(int, const void *, size_t, int);
    void setSendAddr(Elf64_Addr);

    static ssize_t injectWrite(int, const void *, size_t);
    void setWriteAddr(Elf64_Addr);

    static int injectExecve(const char *pathname, char *const argv[],
                            char *const envp[]);
    void setExecveAddr(Elf64_Addr);

    static pid_t injectFork();
    void setForkAddr(Elf64_Addr);
private:
    static Elf64_Addr syscallTable[100];
    static Inject *gInject;
};

#endif