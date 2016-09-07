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
    
    auto process = system::process::get_process_by_name(L"notepad++.exe").front();
    auto ntoskrnl = process.modules()->get_main_module();
    try {
        auto symbol_info = process.symbols()->get_symbol_info_from_address(uintptr_t(ntoskrnl.get_base() + 0x1220));

        auto& module = symbol_info.get_module();

        wcout << hex
            << "Module Name : " << module.get_name() << endl
            << "Module Path : " << module.get_path() << endl
            << "Module Base : " << module.get_base() << endl
            << "Module Size : " << module.get_size() << endl
            << "-----------------------------------------------------" << endl
            << "Symbol Name   : " << symbol_info.get_name() << endl
            << "Symbol Address: " << symbol_info.get_address() << endl
            << "Symbol Offset : " << symbol_info.get_displacement() << endl
            << "-----------------------------------------------------" << endl;

    } catch(const misc::win32_exception& ex) {
        wcout << ex.get_message() << endl;
        wcout << "Status: " << ex.get_status() << endl;
    }

    process = system::process(SYSTEM_PROCESS);
    ntoskrnl = process.modules()->get_main_module();
    try {
        auto symbol_info = process.symbols()->get_symbol_info_from_address(ntoskrnl.get_proc_address("KeTestSpinLock"));

        auto& module = symbol_info.get_module();

        wcout << hex
            << "Module Name : " << module.get_name() << endl
            << "Module Path : " << module.get_path() << endl
            << "Module Base : " << module.get_base() << endl
            << "Module Size : " << module.get_size() << endl
            << "-----------------------------------------------------" << endl
            << "Symbol Name   : " << symbol_info.get_name() << endl
            << "Symbol Address: " << symbol_info.get_address() << endl
            << "Symbol Offset : " << symbol_info.get_displacement() << endl
            << "-----------------------------------------------------" << endl;

    } catch(const misc::win32_exception& ex) {
        wcout << ex.get_message() << endl;
        wcout << "Status: " << ex.get_status() << endl;
    }
    
    ::system("pause");
    return 0;
}