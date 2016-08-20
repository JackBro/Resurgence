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
            const IMAGE_SECTION_HEADER* sections = pe.get_section_header();

            wcout << module.get_name() << endl;

            for(int i = 0;
                i < pe.get_number_of_sections();
                i++) {
                cout << "  " << std::string((const char*)sections[i].Name, size_t(8)) << endl;
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