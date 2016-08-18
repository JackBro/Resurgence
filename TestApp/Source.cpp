#include <iostream>
#include <Windows.h>
#include <resurgence.hpp>
#include <iomanip>

int main(int argc, char** argv) {
    using namespace std;
    using namespace resurgence;
    
    if(!system::process::grant_privilege(SE_DEBUG_PRIVILEGE))
        cout << "[!] Failed to set debug privilege" << endl;
    
    try {
        auto process = system::process::get_current_process();

        for(auto& module : process.modules()->get_all_modules()) {
            auto pe = module.get_pe();
            wcout << setw(32) << left << module.get_name() << " : ";
            if(pe.is_valid()) {
                if(pe._is32Bit) {
                    wcout << hex << pe._ntHdr32.OptionalHeader.ImageBase << endl;
                } else {
                    wcout << hex << pe._ntHdr64.OptionalHeader.ImageBase << endl;
                }
            }
        }

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