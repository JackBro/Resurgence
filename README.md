Resurgence
======

##### A *work in progress* project. 

Resurgence is a x86/x64 game hacking framework, althought it can be used for more than just game hacking (or that is the plan).

Features are limited as of right now (again, WIP).

## Examples:

#### Iterating over processes
```C++
using namespace resurgence;

auto processes = system::process::get_processes();

for(auto& process : processes) {
    wcout << process.get_name() << ": " << ((process.get_platform() == system::platform_x86) ? "x86" : "x64") << endl;
}
```

#### Retrieving process by name
```C++
using namespace resurgence;

auto processes = system::process::get_process_by_name(L"notepad++.exe");

//There can be multiple processes with the same name
for(auto& process : processes) {
    wcout << process.get_name() << ": " << ((process.get_platform() == system::platform_x86) ? "x86" : "x64") << endl;
}
```

#### Listing process modules
```C++
using namespace resurgence;

auto process = system::process::get_current_process();
    
wcout << process.get_name() << endl;
for(auto& module : process.modules()->get_all_modules()) {
    wcout << "    " << module.get_name() << endl;
}
```

#### Reading/Writing to memory
```C++
using namespace resurgence;

auto process = system::process::get_process_by_name(L"notepad++.exe").front();

if(failed(process.open(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)))
  wcout << "Failed to open process" << endl;

auto mainModule = process.modules()->get_module_by_load_order(0);
auto mem        = process.memory();

//Read value
wcout << mem->read<uint8_t>(mainModule.get_base()) << endl;

//Change it
mem->protect(mainModule.get_base(), PAGE_SIZE, PAGE_READWRITE);
mem->write<uint8_t>(mainModule.get_base(), 69);
mem->protect(mainModule.get_base(), PAGE_SIZE, PAGE_READONLY);

//Read again
wcout << mem->read<uint8_t>(mainModule.get_base()) << endl;
```