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
    
    auto process        = system::process(SYSTEM_PROCESS);
    auto ntoskrnl       = process.modules()->get_main_module();
    auto KeTestSpinLock = ntoskrnl.get_proc_address("KeTestSpinLock") + 0x69;
    auto symbol_info    = process.symbols()->get_symbol_info_from_address(KeTestSpinLock);

    auto& module = symbol_info.get_module();

    wcout << hex
          << "Module Name : " << module.get_name() << endl
          << "Module Path : " << module.get_path() << endl
          << "Module Base : " << module.get_base() << endl
          << "Module Size : " << module.get_size() << endl
          << "-----------------------------------------------------" << endl
          << "Symbol Name   : " << symbol_info.get_name()            << endl
          << "Symbol Address: " << symbol_info.get_address()         << endl
          << "Symbol Offset : " << symbol_info.get_displacement()    << endl
          << "-----------------------------------------------------" << endl;
    
    ::system("pause");
    return 0;
}