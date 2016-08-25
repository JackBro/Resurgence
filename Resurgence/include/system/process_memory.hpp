#pragma once

#include <headers.hpp>

namespace resurgence
{
	namespace system
	{
		class process;

		class process_memory
		{
		public:
			process_memory(process* proc);

			uint8_t*                            allocate(size_t size, uint32_t allocation, uint32_t protection);
			NTSTATUS                            allocate_ex(uint8_t** address, size_t size, uint32_t allocation, uint32_t protection);
			NTSTATUS                            protect(const uint8_t* address, size_t size, uint32_t protection, uint32_t* oldProtection = nullptr);
			NTSTATUS                            free(const uint8_t* address, size_t size, uint32_t freeType);
			NTSTATUS                            read_bytes(const uint8_t* address, uint8_t* buffer, size_t size);
			NTSTATUS                            write_bytes(const uint8_t* address, uint8_t* buffer, size_t size);
			template<typename _Ty> _Ty          read(const uint8_t* address);
			template<typename _Ty> void         write(const uint8_t* address, const _Ty& buffer, size_t size = sizeof(_Ty));
			template<typename _Ty> std::string  read_string(_Ty address, size_t length);
			template<typename _Ty> std::wstring read_unicode_string(_Ty address, size_t length);

		private:
			friend class process;
			process_memory();

			process* _process;
		};

		template<typename _Ty> _Ty process_memory::read(const uint8_t* address)
		{
			_Ty buffer;
			read_bytes(address, (uint8_t*)&buffer, sizeof(_Ty));
			return buffer;
		}
		template<typename _Ty> void process_memory::write(const uint8_t* address, const _Ty& buffer, size_t size /*= sizeof(_Ty)*/)
		{
			write_bytes(address, (uint8_t*)&buffer, size);
		}
		template<typename _Ty> std::string process_memory::read_string(_Ty address, size_t length)
		{
			std::string str;
			char* buffer = new char[length + 1]();
			read_bytes((uint8_t*)address, (uint8_t*)buffer, length);
			str = std::string(buffer);
			delete[] buffer;
			return str;
		}
		template<typename _Ty> std::wstring process_memory::read_unicode_string(_Ty address, size_t length)
		{
			std::wstring str;
			wchar_t* buffer = new wchar_t[length + 1]();
			read_bytes((uint8_t*)address, (uint8_t*)buffer, length * sizeof(wchar_t));
			str = std::wstring(buffer);
			delete[] buffer;
			return str;
		}
	}
}
