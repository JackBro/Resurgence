#include <iostream>
#include <string>
#include <Resurgence.hpp>
#include <TlHelp32.h>
#include <algorithm>

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
    using namespace Resurgence;

    System::Driver driver(L".\\ResurgenceDrvWin10.sys");

    ULONG_PTR base;
    UNICODE_STRING uTarget;
    RtlInitUnicodeString(&uTarget, L"ProcessHacker.exe");

    if(NT_SUCCESS(driver.Load())) {
        Misc::NtHelpers::EnumSystemProcesses([&](PSYSTEM_PROCESSES_INFORMATION entry) -> NTSTATUS {
            if(RtlEqualUnicodeString(&uTarget, &entry->ImageName, TRUE)) {
                driver.InjectModule((ULONG)entry->UniqueProcessId, L"C:\\test.dll", TRUE, FALSE, &base);
                wcout << hex << base << endl;
            }
            return STATUS_NOT_FOUND;
        });
    } else {
        wcerr << "Load failed" << endl;
        wcerr << Misc::NtHelpers::GetSystemErrorMessage(GetLastNtStatus()) << endl;
    }

    system("pause");
}