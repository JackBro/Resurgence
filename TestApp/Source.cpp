#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include "resource.h"
#include <resurgence.hpp>
#include <Shlwapi.h>


PVOID mainModule(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    if(Module32First(snap, &me)) {
        CloseHandle(snap);
        return me.modBaseAddr;
    }
    CloseHandle(snap);
    return 0;
}


int main(int argc, char** argv) {
    using namespace std;
    using namespace resurgence;
    
    if(!system::process::grant_privilege(SE_DEBUG_PRIVILEGE))
        cout << "[!] Failed to set debug privilege" << endl;
   
    try {
        auto processes = system::process::get_process_by_name(L"notepad++.exe");
    
        for(auto& process : processes) {
            auto module = process.modules()->get_module_by_name(L"notepad++.exe");
            if(module.get_base() != nullptr) {
                wcout << module.get_base() << endl;
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