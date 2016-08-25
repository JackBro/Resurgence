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

    try {
        system::process_module module;
        auto process = system::process::get_process_by_name(L"notepad++.exe").front();
        process.open(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD);
        process.modules()->inject_module(L"C:\\test_x641.dll", INJECTION_TYPE_LOADLIBRARY, 0, &module);
        wcout << module.get_name() << endl;
        wcout << module.get_base() << endl;

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