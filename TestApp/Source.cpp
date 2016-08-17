#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>
#include "resource.h"
#include <resurgence.hpp>
#include <Shlwapi.h>
#include <iomanip>


int main(int argc, char** argv) {
    using namespace std;
    using namespace resurgence;
    
    if(!system::process::grant_privilege(SE_DEBUG_PRIVILEGE))
        cout << "[!] Failed to set debug privilege" << endl;
    
    try {
        auto process = system::process::get_process_by_name(L"notepad++.exe").front();

        if(failed(process.open(PROCESS_VM_READ | PROCESS_VM_WRITE)))
            wcout << "Failed to open process" << endl;

        auto mainModule = process.modules()->get_module_by_load_order(0);
        auto mem        = process.memory();

        //Read value
        wcout << mem->read<uint8_t>(mainModule.get_base()) << endl;

        //Change it
        //mem->protect(mainModule.get_base(), PAGE_READWRITE);
        mem->write<uint8_t>(mainModule.get_base(), 69);
        //mem->protect(mainModule.get_base(), PAGE_READONLY);

        //Read again
        wcout << mem->read<uint8_t>(mainModule.get_base()) << endl;

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