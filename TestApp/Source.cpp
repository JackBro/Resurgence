#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include "resource.h"
#include <resurgence.hpp>
#include <d3d9.h>

PVOID mainModule(HANDLE pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)(ULONG_PTR)pid);
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
    
    //if(argc < 2) return 1;

    system::driver driver(L".\\ResurgenceDrvWin10.sys");
    
    if(NT_SUCCESS(driver.Load())) {
        VERSION_INFO version;
        if(NT_SUCCESS(driver.QueryVersionInfo(&version)))
            printf("%d %d %d %d %d\n", version.MajorVersion, version.MinorVersion, version.ServicePackMajor, version.ServicePackMinor, version.BuildNumber);
        else {
            wcerr << "failed" << endl;
            wcerr << misc::winnt::get_status_message(get_last_ntstatus()) << endl;
        }
    } else {
        wcerr << "Load failed" << endl;
        wcerr << misc::winnt::get_status_message(get_last_ntstatus()) << endl;
    }
    ::system("pause");
    return 0;
}