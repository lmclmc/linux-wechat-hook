#ifndef EDITSO_H_
#define EDITSO_H_

#include <iostream>
#include <set>

class EditSo
{
public:
    EditSo() = default;
    ~EditSo() = default;

    bool replaceSoDynsym(const std::string &old_name,
                         const std::string &new_name,
                         const std::string &input_soname,
                         const std::string &output_soname);

    bool confuse(const std::string &input_soname,
                 const std::string &output_soname,
                 const std::set<std::string> &filter);
};

#endif