#include <iostream>
#include "injector.h"

uint64_t rva_to_file_offset(const IMAGE_SECTION_HEADER *sections, const size_t num_sections, const uint64_t rva) {
    for (size_t i = 0; i < num_sections; i++) {
        const uint64_t section_start = sections[i].VirtualAddress;
        const uint64_t section_end = section_start + sections[i].Misc.VirtualSize;

        if (rva >= section_start && rva < section_end) {
            return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }
    }

    return 0;
}

void *allocate_dll_buffer(HANDLE handle, const uint64_t image_base, const uint64_t image_size) {
    // Try to allocate at image base, and if we can't, then allocate anywhere in the memory.
    void *allocated = VirtualAllocEx(handle, reinterpret_cast<void *>(image_base), image_size, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (allocated)
        return allocated;

    return VirtualAllocEx(handle, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void base_relocate(char *dll, const uintptr_t buffer_ptr, const IMAGE_NT_HEADERS *nt_headers) {
    // FIXME: I really don't know how is this gonna act if ImageBase > buffer_ptr :)))
    const auto image_delta = buffer_ptr - nt_headers->OptionalHeader.ImageBase;
    if (image_delta == 0) {
        // We don't need to base relocate as we already allocated at the correct image base.
        // Goodbye!
        return;
    }

    const auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
        reinterpret_cast<const char *>(&nt_headers->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.
        SizeOfOptionalHeader
    );

    // Iterate through sections
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER section = sections[i];

        // Check if section matches name ".reloc"
        char name[9] = {};
        memcpy(name, section.Name, 8);
        if (strcmp(name, ".reloc") != 0)
            continue;

        IMAGE_BASE_RELOCATION *relocation_block;
        size_t offset = section.PointerToRawData;

        // Iterates through every relocation block.
        while ((relocation_block = reinterpret_cast<IMAGE_BASE_RELOCATION *>(dll + offset))->SizeOfBlock >= sizeof(
                   IMAGE_BASE_RELOCATION)) {
            const auto words = reinterpret_cast<WORD *>(relocation_block + 1);
            const auto words_len = (relocation_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (int j = 0; j < words_len; j++) {
                const int word_flag = words[j] >> 12;
                const int word_offset = words[j] & 0xFFF;
                switch (word_flag) {
                    // Perhaps handle every flag?
                    case IMAGE_REL_BASED_DIR64:
                        const uint64_t file_offset = rva_to_file_offset(
                            sections, nt_headers->FileHeader.NumberOfSections,
                            relocation_block->VirtualAddress + word_offset);
                        auto *ptr = reinterpret_cast<uintptr_t *>(dll + file_offset);
                        *ptr += image_delta;
                        break;
                }
            }
            offset += relocation_block->SizeOfBlock;
        }
    }

    std::cout << "[*] relocated image base" << std::endl;
}

bool write_dll_header(HANDLE handle, const char *dll, const uintptr_t ptr, const IMAGE_DOS_HEADER *dos_header) {
    const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(dll + dos_header->e_lfanew);
    // Write DOS header
    std::cout << "[*] writing DOS header" << std::endl;
    if (!WriteProcessMemory(handle, reinterpret_cast<LPVOID>(ptr), dos_header, sizeof(IMAGE_DOS_HEADER), nullptr))
        return false;
    // Write NT headers
    std::cout << "[*] writing NT headers" << std::endl;
    if (!WriteProcessMemory(handle, reinterpret_cast<LPVOID>(ptr + dos_header->e_lfanew), nt_headers,
                            sizeof(IMAGE_NT_HEADERS), nullptr))
        return false;

    const auto sec_offset = dos_header->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + nt_headers->
                            FileHeader.SizeOfOptionalHeader;

    // Write section headers
    const auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(dll + sec_offset);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER section = sections[i];
#ifdef MANUAL_MAP_DEBUG
        std::cout << "[*] writing section header " << section.Name << std::endl;
#endif
        if (!WriteProcessMemory(handle, reinterpret_cast<LPVOID>(ptr + sec_offset + i * sizeof(IMAGE_SECTION_HEADER)),
                                &section, sizeof(IMAGE_SECTION_HEADER), nullptr))
            return false;
    }
    return true;
}

bool map_sections(HANDLE handle, const char *dll, const uintptr_t ptr, const IMAGE_NT_HEADERS *nt_headers) {
    const auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
        reinterpret_cast<const char *>(&nt_headers->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.
        SizeOfOptionalHeader
    );

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        const IMAGE_SECTION_HEADER section = sections[i];
#ifdef MANUAL_MAP_DEBUG
        std::cout << "[*] mapping section " << section.Name << " at " << (ptr + section.VirtualAddress) << " of size: " << section.Misc.VirtualSize << std::endl;
#endif
        if (!WriteProcessMemory(handle, reinterpret_cast<LPVOID>(ptr + section.VirtualAddress),
                                dll + section.PointerToRawData, section.SizeOfRawData, nullptr)) {
            return false;
        }
    }
    return true;
}

bool manual_map(DWORD process_id, char *dll) {
    const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(dll);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] invalid DOS header!" << std::endl;
        return false;
    }

    const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(dll + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] invalid NT headers!" << std::endl;
        return false;
    }

    HANDLE process_handle = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | /*PROCESS_VM_READ | */PROCESS_VM_WRITE, false, process_id);
    if (!process_handle) {
        std::cerr << "[!] OpenProcess failed!" << std::endl;
        return false;
    }

    void *dll_buffer = allocate_dll_buffer(process_handle, nt_headers->OptionalHeader.ImageBase,
                                           nt_headers->OptionalHeader.SizeOfImage);
    if (!dll_buffer) {
        std::cerr << "[!] VirtualAllocEx failed!" << std::endl;
        CloseHandle(process_handle);
        return false;
    }

    std::cout << "[*] allocated " << nt_headers->OptionalHeader.SizeOfImage << " bytes at 0x" << std::hex << dll_buffer
            << std::dec << std::endl;
    base_relocate(dll, reinterpret_cast<uintptr_t>(dll_buffer), nt_headers);

    if (!write_dll_header(process_handle, dll, reinterpret_cast<uintptr_t>(dll_buffer), dos_header)) {
        std::cerr << "[!] DLL Header writing failed!" << std::endl;
        VirtualFreeEx(process_handle, dll_buffer, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return false;
    }

    std::cout << "[*] wrote DLL header" << std::endl;
    if (!map_sections(process_handle, dll, reinterpret_cast<uintptr_t>(dll_buffer), nt_headers)) {
        std::cerr << "[!] sections mapping failed!" << std::endl;
        VirtualFreeEx(process_handle, dll_buffer, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return false;
    }

    std::cout << "[*] mapped sections" << std::endl;
    const t_loader_stub stub = {
        .load_library_ptr = reinterpret_cast<void*>(LoadLibraryA),
        .get_proc_address_ptr = reinterpret_cast<void*>(GetProcAddress),
        .dll_base = dll_buffer,
    };

    // Write loader stub data to our process.
    void *stub_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(t_loader_stub), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stub_buffer || !WriteProcessMemory(process_handle, stub_buffer, &stub, sizeof(t_loader_stub), nullptr)) {
        std::cerr << "[!] stub buffer VirtualAllocEx/WPM failed!" << std::endl;
        VirtualFreeEx(process_handle, dll_buffer, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return false;
    }
    std::cout << "[*] wrote stub buffer" << std::endl;

    // Now we write our loader stub function...
    void *shellcode_buffer = VirtualAllocEx(process_handle, nullptr, 0x800, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode_buffer || !WriteProcessMemory(process_handle, shellcode_buffer, reinterpret_cast<LPCVOID>(&loader_stub), 0x800, nullptr)) {
        std::cerr << "[!] shellcode buffer VirtualAllocEx/WPM failed!" << std::endl;
        VirtualFreeEx(process_handle, dll_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(process_handle, shellcode_buffer, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        return false;
    }
    std::cout << "[*] wrote shellcode" << std::endl;

    // Now, we open a thread calling our shellcode.
    CreateRemoteThread(process_handle, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode_buffer), stub_buffer, 0, nullptr);
    std::cout << "[*] created remote thread running shellcode" << std::endl;

    CloseHandle(process_handle);
    return true;
}

#ifdef _MSC_VER
#pragma optimize("", off)
#pragma runtime_checks("", off) // That makes it work when injector is built in debug mode
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__ ((optimize("O0")))
__attribute__ ((noinline))
#endif
// Shellcode here that will resolve IAT, call TLS callbacks, and then finally DllMain.
// Yes, LoadLibraryA and GetProcAddress are static addresses, we are assuming that kernel32.dll is always allocated at the same image base.
void loader_stub(const t_loader_stub *stub) {
    const auto stub_dll_base_ptr = reinterpret_cast<uintptr_t>(stub->dll_base);

    const auto dos_header = static_cast<IMAGE_DOS_HEADER *>(stub->dll_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS *>(stub_dll_base_ptr + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        return;

    const auto LoadLibraryA_ = reinterpret_cast<t_load_library>(stub->load_library_ptr);
    const auto GetProcAddress_ = reinterpret_cast<t_get_proc_address>(stub->get_proc_address_ptr);

    // Resolve import address table (IAT).
    if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) {
        auto import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(
            stub_dll_base_ptr + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (import_descriptor->Name) {
            HINSTANCE import_dll = LoadLibraryA_(reinterpret_cast<char *>(stub_dll_base_ptr + import_descriptor->Name));

            const auto original_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                stub_dll_base_ptr + (import_descriptor->OriginalFirstThunk
                                         ? import_descriptor->OriginalFirstThunk
                                         : import_descriptor->FirstThunk));
            const auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                stub_dll_base_ptr + import_descriptor->FirstThunk);
            int i = 0;

            while (original_first_thunk[i].u1.AddressOfData) {
                const ULONGLONG ordinal = original_first_thunk[i].u1.Ordinal;
                if (IMAGE_SNAP_BY_ORDINAL(ordinal)) {
                    first_thunk[i].u1.Function = reinterpret_cast<ULONG_PTR>(GetProcAddress_(
                        import_dll, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(ordinal))));
                } else {
                    const auto image_by_import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                        stub_dll_base_ptr + original_first_thunk[i].u1.AddressOfData);
                    first_thunk[i].u1.Function = reinterpret_cast<ULONG_PTR>(GetProcAddress_(
                        import_dll, reinterpret_cast<char *>(image_by_import_name->Name)));
                }
                i++;
            }

            import_descriptor++;
        }
    }

    // Call TLS (Thread Local Storage) callbacks.
    if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0) {
        const auto tls_directory = reinterpret_cast<IMAGE_TLS_DIRECTORY *>(
            stub_dll_base_ptr + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto tls_callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(tls_directory->AddressOfCallBacks);
        while (*tls_callbacks) {
            (*tls_callbacks)(static_cast<PVOID>(stub->dll_base), DLL_PROCESS_ATTACH, nullptr);
            tls_callbacks++;
        }
    }

    // Finally, call our DLL's entry point.
    reinterpret_cast<t_dll_main>(reinterpret_cast<uintptr_t>(stub->dll_base) + nt_headers->OptionalHeader.
                                 AddressOfEntryPoint)(static_cast<HINSTANCE>(stub->dll_base), DLL_PROCESS_ATTACH,
                                                      nullptr);
}
#ifdef _MSC_VER
#pragma optimize("", on)
#pragma runtime_checks("", restore)
#endif
