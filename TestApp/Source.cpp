#include <iostream>
#include <string>
#include <Resurgence.hpp>
#include <TlHelp32.h>

PVOID mainModule(HANDLE pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)pid);
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
    NTSTATUS status;
    System::Driver driver(L".\\ResurgenceDrvWin10.sys");
    if(NT_SUCCESS(driver.Load())) {
        Misc::NtHelpers::EnumSystemProcesses([&](PSYSTEM_PROCESSES_INFORMATION info) -> NTSTATUS {
            //wcout << info->UniqueProcessId << endl;
            if(RtlCompareMemory(info->ImageName.Buffer, L"notepad.exe", info->ImageName.Length)) {
                HANDLE handle;
                DWORD buffer;
                if(NT_SUCCESS(driver.OpenProcess((ULONG)info->UniqueProcessId, PROCESS_VM_OPERATION | PROCESS_VM_READ, &handle))) {
                    wcout << "Success" << endl;
                    if(ReadProcessMemory(handle, mainModule(info->UniqueProcessId), &buffer, sizeof(DWORD), NULL)) {
                        wcout << hex << buffer << endl;
                    } else {
                        wcerr << "ReadProcessMemory failed" << endl;
                        wcerr << Misc::NtHelpers::GetSystemErrorMessage(GetLastNtStatus()) << endl;
                    }
                } else {
                    wcerr << "OpenProcess failed" << endl;
                    wcerr << Misc::NtHelpers::GetSystemErrorMessage(GetLastNtStatus()) << endl;
                }
                return STATUS_SUCCESS;
            }
            return STATUS_NOT_FOUND;
        });
    } else {
        wcerr << "Load failed" << endl;
        wcerr << Misc::NtHelpers::GetSystemErrorMessage(GetLastNtStatus()) << endl;
    }

    system("pause");
}