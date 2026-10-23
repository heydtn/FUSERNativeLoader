#pragma once
#include <cstddef>
#include <cstdint>

#include <Windows.h>

inline IMAGE_NT_HEADERS *nt_headers(uint8_t *module) {
    return reinterpret_cast<IMAGE_NT_HEADERS *>(module + reinterpret_cast<IMAGE_DOS_HEADER *>(module)->e_lfanew);
}

template <typename Visit>
void visit_named_imports(uint8_t *module, const char *dll, DWORD names_rva, DWORD slots_rva, Visit &visit) {
    auto *names = reinterpret_cast<IMAGE_THUNK_DATA *>(module + names_rva);
    auto *slots = reinterpret_cast<IMAGE_THUNK_DATA *>(module + slots_rva);
    for (; names->u1.AddressOfData; names++, slots++) {
        if (!IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) {
            auto *by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(module + names->u1.AddressOfData);
            visit(dll, reinterpret_cast<const char *>(by_name->Name), reinterpret_cast<void **>(&slots->u1.Function));
        }
    }
}

template <typename Visit>
void for_each_import(uint8_t *module, Visit visit) {
    const IMAGE_DATA_DIRECTORY &imports =
        nt_headers(module)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto *descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(module + imports.VirtualAddress);
    for (; imports.VirtualAddress && descriptor->Name; descriptor++) {
        if (descriptor->OriginalFirstThunk) {
            const char *dll = reinterpret_cast<const char *>(module + descriptor->Name);
            visit_named_imports(module, dll, descriptor->OriginalFirstThunk, descriptor->FirstThunk, visit);
        }
    }
}

template <typename Visit>
void for_each_delay_import(uint8_t *module, Visit visit) {
    const IMAGE_DATA_DIRECTORY &imports =
        nt_headers(module)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    auto *descriptor = reinterpret_cast<IMAGE_DELAYLOAD_DESCRIPTOR *>(module + imports.VirtualAddress);
    for (; imports.VirtualAddress && descriptor->DllNameRVA && descriptor->Attributes.RvaBased; descriptor++) {
        const char *dll = reinterpret_cast<const char *>(module + descriptor->DllNameRVA);
        visit_named_imports(module, dll, descriptor->ImportNameTableRVA, descriptor->ImportAddressTableRVA, visit);
    }
}
