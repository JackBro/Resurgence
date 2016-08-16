#include <system/process_modules.hpp>
#include <system/process.hpp>
#include <misc/exceptions.hpp>
#include <misc/winnt.hpp>

namespace resurgence
{
    namespace system
    {
        auto startsWith = [](const std::wstring& str1, const std::wstring& str2, bool ignoreCasing) {
            if(ignoreCasing) {
                std::wstring copy1 = str1, copy2 = str2;
                std::transform(copy1.begin(), copy1.end(), copy1.begin(), ::tolower);
                std::transform(copy2.begin(), copy2.end(), copy2.begin(), ::tolower);
                return copy1.compare(0, copy2.size(), copy2) == 0;
            } else {
                return str1.compare(0, str2.size(), str2) == 0;
            }
        };

        process_module::process_module()
        {
            RtlZeroMemory(this, sizeof(*this));
        }
        process_module::process_module(process* proc, PLDR_DATA_TABLE_ENTRY entry)
        {
            if(proc->is_current_process()) {
                _base = (uint8_t*)entry->DllBase;
                _size = (size_t)entry->SizeOfImage;
                _name = entry->BaseDllName.Buffer;
                _path = entry->FullDllName.Buffer;
            } else {
                _base = (uint8_t*)entry->DllBase;
                _size = (size_t)entry->SizeOfImage;
                _name = proc->memory()->read_unicode_string(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t));
                _path = proc->memory()->read_unicode_string(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(wchar_t));
            }
        }
        process_module::process_module(process* proc, PLDR_DATA_TABLE_ENTRY32 entry)
        {
            _base = (uint8_t*)entry->DllBase;
            _size = (size_t)entry->SizeOfImage;
            _name = proc->memory()->read_unicode_string(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t));
            _path = proc->memory()->read_unicode_string(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(wchar_t));

            auto system32 = std::wstring(USER_SHARED_DATA->NtSystemRoot) + L"\\System32";
            auto syswow64 = std::wstring(USER_SHARED_DATA->NtSystemRoot) + L"\\SysWOW64";
            if(startsWith(_path, std::wstring(USER_SHARED_DATA->NtSystemRoot) + L"\\System32", TRUE)) {
                _path = _path.replace(0, system32.size(), syswow64);
            }
        }
        process_module::process_module(PRTL_PROCESS_MODULE_INFORMATION entry)
        {
            wchar_t path[MAX_PATH] = {NULL};
            MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (const char*)entry->FullPathName, 256, path, MAX_PATH);

            _base = (uint8_t*)entry->ImageBase;
            _size = (size_t)entry->ImageSize;
            _name = (path + entry->OffsetToFileName);
            _path = misc::winnt::get_dos_path(path);
        }

        process_modules::process_modules(process* proc)
            : _process(proc)
        {
        }
        process_modules::process_modules()
            : _process(nullptr)
        {

        }
        std::vector<process_module> process_modules::get_all_modules()
        {
            using namespace misc;
            assert(_process != nullptr);

            std::vector<process_module> modules;

            auto id = _process->get_pid();
            auto handle = _process->get_handle();

            if(!_process->is_system_idle_process()) {
                if(_process->is_system_process()) {
                    winnt::enumerate_system_modules([&](PRTL_PROCESS_MODULE_INFORMATION info) {
                        modules.emplace_back(info);
                        return STATUS_NOT_FOUND;
                    });
                } else if(handle.is_valid()) {
                    winnt::enumerate_process_modules(handle.get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                        modules.emplace_back(_process, entry);
                        return STATUS_NOT_FOUND;
                    });

                #ifdef _WIN64
                    if(_process->get_platform() == platform_x86) {
                        std::vector<process_module> modules32;
                        winnt::enumerate_process_modules32(handle.get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
                            modules32.emplace_back(_process, entry);
                            return STATUS_NOT_FOUND;
                        });
                        if(modules32.size() > 1) {
                            auto begin = ++std::begin(modules32);
                            auto end = std::end(modules32);
                            modules.insert(std::end(modules), begin, end);
                        }
                    }
                #endif

                }
            }
            return modules;
        }
        process_module process_modules::get_module_by_name(const std::wstring& name)
        {
            process_module mod;
        #ifdef _WIN64
            if(_process->get_platform() == platform_x86) {
                misc::winnt::enumerate_process_modules32(_process->get_handle().get(), [&](PLDR_DATA_TABLE_ENTRY32 entry) {
                    auto buffer
                        = _process->memory()->read_unicode_string(
                            entry->BaseDllName.Buffer,
                            entry->BaseDllName.Length / sizeof(wchar_t));
                    if(buffer == name) {
                        mod = process_module(_process, entry);
                        return STATUS_SUCCESS;
                    }
                    return STATUS_NOT_FOUND;
                });
                return mod;
            } else {
        #endif
                misc::winnt::enumerate_process_modules(_process->get_handle().get(), [&](PLDR_DATA_TABLE_ENTRY entry) {
                    auto buffer
                        = _process->memory()->read_unicode_string(
                            entry->BaseDllName.Buffer,
                            entry->BaseDllName.Length / sizeof(wchar_t));
                    if(buffer == name) {
                        mod = process_module(_process, entry);
                        return STATUS_SUCCESS;
                    }
                    return STATUS_NOT_FOUND;
                });
                return mod;
        #ifdef _WIN64
            }
        #endif
        }
        process_module process_modules::get_module_by_handle(HANDLE handle)
        {
            throw;
        }
        process_module process_modules::get_module_by_load_order(int i)
        {
            throw;
        }
    }
}