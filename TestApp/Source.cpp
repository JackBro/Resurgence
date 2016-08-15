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
    
    auto processes = system::process::get_processes();
    
    for(auto& process : processes) {
        wcout << (PVOID)process.get_peb_address() << " | " << process.get_name() << endl;
        //for(auto& module : process.modules()->get_all_modules()) {
        //    wcout << "    " << module.get_path() << endl;
        //}
        //wcout << endl;
    }

    ::system("pause");
    return 0;
}