#include "eviluser.h"
#include "target/targetopt.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <memory>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_TMPBUFFER_SIZE 100000
static int sockFd = 0;

#define COLOR_RED       "\e[1;31m"        //鲜红
#define COLOR_GREEN       "\e[0;32m"         //深绿，暗绿
#define COLOR_NONE      "\e[0m" 

EvilUser::EvilUser() :
    tmpBuffer(nullptr)
{}

EvilUser::~EvilUser()
{
    if (tmpBuffer)
        free(tmpBuffer);
}

int BinaryFind(const unsigned char * Dest, int DestLen, 
               const unsigned char * Src, int SrcLen)   
{   
	int j = 0;
	for (int i=0; i<DestLen; i++)   
	{   
		for (j=0; j<SrcLen; j++)   
			if (Dest[i+j] != Src[j])	
				break;
		if (j == SrcLen) 
			return i;
	}   
	return -1;	
}

bool searchBinary(int sockFd, struct sockaddr_in *client, Elf64_Addr baseAddr, 
                  int size, unsigned char *str, int strSize)
{
    int ret = 0;
    unsigned char *p = (unsigned char *)baseAddr;
    bool status = false;
    char buffer[4096] = {0};
    char *c = NULL;
    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        ret = BinaryFind(p, (unsigned char *)baseAddr+size-p, str, strSize);
        if (ret < 0)
        {
            if (status)
                return true;
            return false;
        }
            
        status = true;
        p += ret;

        snprintf(buffer, sizeof(buffer), "str = %s, addr = %p\n", p, p);
        sendto(sockFd, buffer, strlen(buffer), 0,(struct sockaddr*)client,sizeof(*client)); 
        p += 1;

        if (p - (unsigned char *)baseAddr >= size)
            return true;
    }      
}

struct sockaddr_in local;
void EvilUser::evilMain()
{
    // TargetMaps t(getpid());
    // t.readTargetAllMaps();
    // std::list<MapInfo> l = t.getMapInfo();

    // if (!sockFd)
    // {
    //     sockFd = socket(AF_INET,SOCK_DGRAM,0);
    //     struct sockaddr_in local;
    //     local.sin_family=AF_INET;
    //     local.sin_port = htons(11111);
    //     local.sin_addr.s_addr = inet_addr("127.0.0.1");
    //     bind(sockFd, (struct sockaddr*)&local, sizeof(local));
    // }

    // char buf[1024] = {0};
    // struct sockaddr_in remote;
    // socklen_t len=sizeof(remote);
    // char buffer[256] = {0};
    // char *finishStr = COLOR_GREEN"=========================finish========================="COLOR_NONE"\n";
    // while(1)
    // {
    //     memset(buf, 0, sizeof(buf));
    //     memset(buffer, 0, sizeof(buffer));
    //     ssize_t _s = recvfrom(sockFd, buf, sizeof(buf)-1 , 0 , (struct sockaddr*)&remote, &len);
    //     if (!strncmp(buf, "X", 1) || strlen(buf) < 5) continue;
    //     *(char *)strchr(buf, '\n') = '\0';
        
    //     snprintf(buffer, sizeof(buffer), COLOR_GREEN"=========================start=========================" 
    //             "\nstr = \"%s\", size = %d\n"COLOR_NONE, buf, strlen(buf));

    //     sendto(sockFd, buffer, strlen(buffer), 0,(struct sockaddr*)&remote,sizeof(remote));
    //     for (auto &s : l)
    //     {
    //         if (s.mapName.find("libinject.so") != std::string::npos) continue;
    //         if (searchBinary(sockFd, &remote, s.baseAddr, s.size, (unsigned char *)buf, strlen(buf)))
    //         {
    //             snprintf(buffer, sizeof(buffer), COLOR_RED"SO base = %p, size = %lx, name = %s\n"COLOR_NONE, 
    //                 s.baseAddr, s.size, s.mapName.c_str());
    //             sendto(sockFd, buffer, strlen(buffer), 0,(struct sockaddr*)&remote,sizeof(remote)); 
    //         }
    //     }

    //     sendto(sockFd, finishStr, strlen(finishStr), 0,(struct sockaddr*)&remote,sizeof(remote)); 
    // }
}

ssize_t EvilUser::evilAccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return 0;
}

ssize_t EvilUser::evilRead(int fd, void *buf, size_t count)
{
    return 0;
}

ssize_t EvilUser::evilSend(int sockfd, const void *buf, size_t len, int flags)
{
    return 0;
}

pid_t EvilUser::evilFork(pid_t pid)
{
    char buffer[128] = {0};
    sprintf(buffer, "pid = %d\n", pid);
    echo_printf(buffer, strlen(buffer));
    return 0;
}

ssize_t EvilUser::evilWrite(int fd, const void *buf, size_t count)
{
    if (fd == 1 || fd == 2)
    {
        echo_printf((const char *)buf, count);
       // echo_printf("\n", 1);
    }
    // if (!tmpBuffer)
    //     tmpBuffer = (char *)malloc(MAX_TMPBUFFER_SIZE);

    // char *p = NULL;
    // char *injectLink = "  https://github.com/lmclmc/mem-infector";
    // char *wikiLink = "https://wiki.apache.org/tomcat/FrontPage";

    // size_t retSize = 0;
    // if ((p = (char *)strstr((const char *)buf, wikiLink)))
    // {
    //     int wikiLinkSize = strlen(wikiLink);
    //     memcpy(p, injectLink, wikiLinkSize);
    // }

    return 0;
}

int EvilUser::evilExecve(const char *pathname, char *const argv[],
                         char *const envp[])
{
    echo_printf(pathname, strlen(pathname));
    // echo_printf("\n");
    // for (int i = 0; i < 100; i++)
    // {
    //     if (argv[i] == NULL)
    //         break;
        
    //     echo_printf(argv[i]);
    //     echo_printf("\n");
    // }
    return 0;
}

void echo_printf(const char *src, int len)
{
    int fd = open("/home/lmc/Desktop/tmp.log", O_CREAT | O_APPEND | O_RDWR, 0666);
    write(fd, src, len);
    close(fd);
}