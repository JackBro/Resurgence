#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include "resource.h"
#include <resurgence.hpp>
#include <Shlwapi.h>
#include <iomanip>


int main(int argc, char** argv) {
    using namespace std;
    using namespace resurgence;
    
    if(!system::process::grant_privilege(SE_DEBUG_PRIVILEGE))
        cout << "[!] Failed to set debug privilege" << endl;
    
    try {
        auto processes = system::process::get_processes();
    
        for(auto& process : processes) {
            wcout
                << setw(50)
                << setfill(L' ')
                << left
                << process.get_name();

            auto modules = process.modules()->get_all_modules();
            if(modules.size() > 0) {
                auto module = modules.front();
                if(module.is_valid()) {
                    uint8_t bytes[4];
                    wcout
                        << module.get_base()
                        << ": ";
                    if(succeeded(process.memory()->read_bytes(module.get_base(), bytes, 4))) {
                        for(auto& byte : bytes) {
                            wcout
                                << hex
                                << right
                                << setw(2)
                                << setfill(L'0')
                                << byte
                                << " ";
                        }
                        wcout << endl;
                    } else {
                        wcout << "Read failed. Status: " << hex << get_last_ntstatus() << endl;
                    }
                }
            } else {
                wcout << "Failed to get modules. Status: " << hex << get_last_ntstatus() << endl;
            }
        }
    } catch(const misc::exception& ex) {
        wcout << ex.get_message() << endl;
        if(dynamic_cast<const misc::win32_exception*>(&ex)) {
            const misc::win32_exception& w32 = static_cast<const misc::win32_exception&>(ex);
            wcout << misc::winnt::get_status_message(w32.get_status()) << endl;
        }
    }

    ::system("pause");
    return 0;
}