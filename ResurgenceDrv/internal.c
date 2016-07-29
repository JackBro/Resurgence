#include "internal.h"

#pragma alloc_text(PAGE, ExpLookupHandleTableEntry)

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(
    __in PHANDLE_TABLE HandleTable,
    __in EXHANDLE ExHandle
)
{
#ifdef _WIN10_
    ULONG_PTR HandleValue;      // rdx@1
    ULONG_PTR TableCode;        // r8@2
    ULONG_PTR TableLevel;       // rax@2
    ULONG_PTR HandleArray;      // rax@3
    PHANDLE_TABLE_ENTRY result; // rax@4

    HandleValue = ExHandle.Value & 0xFFFFFFFFFFFFFFFCui64;
    if(HandleValue >= HandleTable->NextHandleNeedingPool) {
        result = NULL;
    } else {
        TableCode = HandleTable->TableCode;
        TableLevel = HandleTable->TableCode & 3;
        if(TableLevel == 1) {
            HandleArray = *(ULONG_PTR*)(TableCode + 8 * (HandleValue >> 10) - 1);
            return (PHANDLE_TABLE_ENTRY)(HandleArray + 4 * (HandleValue & 0x3FF));
        }
        if(TableLevel) {
            HandleArray = *(ULONG_PTR*)(*(ULONG_PTR*)(TableCode + 8 * (HandleValue >> 19) - 2) + 8 * ((HandleValue >> 10) & 0x1FF));
            return (PHANDLE_TABLE_ENTRY)(HandleArray + 4 * (HandleValue & 0x3FF));
        }
        result = (PHANDLE_TABLE_ENTRY)(TableCode + 4 * HandleValue);
    }
    return result;
#else
#error "Unsupported"
#endif
}
