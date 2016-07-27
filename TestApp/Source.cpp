#include <iostream>
#include <string>
#include <Resurgence.hpp>
#include <TlHelp32.h>

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
    if(NT_SUCCESS(driver.Load())) {

    } else {
        wcerr << "Load failed" << endl;
        wcerr << Misc::NtHelpers::GetSystemErrorMessage(GetLastNtStatus()) << endl;
    }

    system("pause");
}