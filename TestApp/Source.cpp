#include <iostream>
#include <Windows.h>
#include <resurgence.hpp>
#include <iomanip>

int main(int argc, char** argv)
{
    using namespace std;
    using namespace resurgence;

    if(!system::process::grant_privilege(SE_DEBUG_PRIVILEGE))
        cout << "[!] Failed to set debug privilege" << endl;

    for(auto& proc : system::process::get_process_by_name(L"lsass.exe")) {
        auto name = proc.get_name();
        if(name.size() > 15) {
            name = name.substr(0, 15).append(L"...");
        }
        try {
            printf("[%-20ws]: %d\n", name.data(), proc.threads()->get_all_threads().size());
        } catch(const misc::exception& ex) {
            printf("[%-20ws]: %ws\n", name.data(), ex.get_message().data());
        }
    }
    
    ::system("pause");
    return 0;
}