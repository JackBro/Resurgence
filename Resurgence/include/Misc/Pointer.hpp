#pragma once

#include <cstdint>

class ptr_t
{
public:
    ptr_t() : _ptr(0) {}
    ptr_t(void* ptr) : _ptr((uintptr_t)ptr) {}
    ptr_t(uintptr_t ptr) : _ptr(ptr) {}

    ptr_t operator*()
    {
        return *reinterpret_cast<uintptr_t*>(_ptr);
    }

    template<typename Ty>
    Ty Get() const
    {
        return *(Ty*)&_ptr;
    }


    operator void*() { return reinterpret_cast<void*>(_ptr); }
    operator const void*() const { return reinterpret_cast<const void*>(_ptr); }

    operator uintptr_t() const { return _ptr; }
    operator bool() const { return _ptr != 0; }
private:
    uintptr_t _ptr;
};
