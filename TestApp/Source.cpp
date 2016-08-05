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
    
    if(argc < 2) return 1;

    system::driver driver(L".\\ResurgenceDrvWin10.sys");
    
    ULONG_PTR base;
    UNICODE_STRING uTarget;
    RtlInitUnicodeString(&uTarget, L"csgo.exe");
    
    if(NT_SUCCESS(driver.Load())) {
        misc::winnt::enumerate_processes([&](PSYSTEM_PROCESSES_INFORMATION entry) -> NTSTATUS {
            if(RtlEqualUnicodeString(&uTarget, &entry->ImageName, TRUE)) {
                WCHAR path[MAX_PATH];
                MultiByteToWideChar(CP_UTF8, 0, argv[1], strlen(argv[1]), path, sizeof(path));
                wcout << path << endl;
                driver.InjectModule((ULONG)entry->UniqueProcessId, path, FALSE, FALSE, &base);
                wcout << hex << base << endl;
            }
            return STATUS_NOT_FOUND;
        });
    } else {
        wcerr << "Load failed" << endl;
        wcerr << misc::winnt::get_status_message(get_last_ntstatus()) << endl;
    }

    return 0;
}