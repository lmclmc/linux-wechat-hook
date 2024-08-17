#ifndef TARGETOPT_H_
#define TARGETOPT_H_

#include <string>
#include <elf.h>
#include <map>

class TargetMaps
{
public:
    TargetMaps(int);
    virtual ~TargetMaps(){}

    void clearMapInfos();
    bool readTargetAllMaps();
    std::map<std::string, Elf64_Addr> &getMapInfo();

private:
    int pid;
    std::map<std::string, Elf64_Addr> mapInfos;
};

class TargetOpt : public TargetMaps
{
public:
    TargetOpt(int);

    bool attachTarget();

    bool detechTarget();

    bool readTarget(unsigned long, void *, int);

    bool writeTarget(unsigned long, const void *, int);

    bool readTarget(struct user_regs_struct &);

    bool writeTarget(struct user_regs_struct &);

    bool contTarget();

    bool stepTarget();

private:
    int pid;

    bool isAttach;
};

#endif