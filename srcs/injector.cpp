#include <iostream>
#include <cstring>

#include "injector.h"
#include "syscalls.h"
#include <tlhelp32.h>

#define SHELLCODE_BUFFER_SIZE (2 << 10)

// rva_to_file_offset 函数保持不变
uint64_t rva_to_file_offset(const IMAGE_SECTION_HEADER *sections, const size_t num_sections, const uint64_t rva)
{
    for (size_t i = 0; i < num_sections; i++)
    {
        const uint64_t section_start = sections[i].VirtualAddress;
        const uint64_t section_end = section_start + sections[i].Misc.VirtualSize;
        if (rva >= section_start && rva < section_end)
        {
            return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }
    }
    return 0;
}

// 新的内存分配函数，使用节对象映射技术
PVOID allocate_memory_via_section(HANDLE hProcess, SIZE_T size, HANDLE &hSection)
{
    NTSTATUS status;
    PVOID remoteBaseAddress = nullptr;
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = size;

    status = MyNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (status != 0 || hSection == NULL)
    {
        std::cerr << "[-] MyNtCreateSection failed! NTSTATUS: 0x" << std::hex << status << std::endl;
        return nullptr;
    }

    SIZE_T viewSize = 0;
    status = MyNtMapViewOfSection(
        hSection,
        hProcess,
        &remoteBaseAddress,
        0, 0, NULL, &viewSize,
        1,
        0,
        PAGE_EXECUTE_READWRITE);
    if (status != 0 || remoteBaseAddress == nullptr)
    {
        std::cerr << "[-] MyNtMapViewOfSection failed! NTSTATUS: 0x" << std::hex << status << std::endl;
        MyNtClose(hSection);
        hSection = NULL;
        return nullptr;
    }

    return remoteBaseAddress;
}

// base_relocate 函数保持不变
void base_relocate(char *dll, const uintptr_t buffer_ptr, const IMAGE_NT_HEADERS *nt_headers)
{
    const auto image_delta = buffer_ptr - nt_headers->OptionalHeader.ImageBase;
    if (image_delta == 0)
        return;

    const auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
        reinterpret_cast<const char *>(&nt_headers->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        const IMAGE_SECTION_HEADER section = sections[i];
        char name[9] = {};
        memcpy(name, section.Name, 8);
        if (strcmp(name, ".reloc") != 0)
            continue;

        IMAGE_BASE_RELOCATION *relocation_block;
        size_t offset = section.PointerToRawData;

        while ((relocation_block = reinterpret_cast<IMAGE_BASE_RELOCATION *>(dll + offset))->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            const auto words = reinterpret_cast<WORD *>(relocation_block + 1);
            const auto words_len = (relocation_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (size_t j = 0; j < words_len; j++)
            {
                const int word_flag = words[j] >> 12;
                const int word_offset = words[j] & 0xFFF;
                if (word_flag == IMAGE_REL_BASED_DIR64)
                {
                    const uint64_t file_offset = rva_to_file_offset(sections, nt_headers->FileHeader.NumberOfSections, relocation_block->VirtualAddress + word_offset);
                    auto *ptr = reinterpret_cast<uintptr_t *>(dll + file_offset);
                    *ptr += image_delta;
                }
            }
            offset += relocation_block->SizeOfBlock;
        }
    }
    std::cout << "[*] relocated image base" << std::endl;
}

// write_dll_header 函数保持不变
bool write_dll_header(HANDLE handle, const char *dll, const uintptr_t ptr, const IMAGE_DOS_HEADER *dos_header)
{
    const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(dll + dos_header->e_lfanew);
    std::cout << "[*] writing DOS header" << std::endl;
    if (MyNtWriteVirtualMemory(handle, reinterpret_cast<LPVOID>(ptr), (PVOID)dos_header, sizeof(IMAGE_DOS_HEADER), nullptr) != 0)
        return false;
    std::cout << "[*] writing NT headers" << std::endl;
    if (MyNtWriteVirtualMemory(handle, reinterpret_cast<LPVOID>(ptr + dos_header->e_lfanew), (PVOID)nt_headers, sizeof(IMAGE_NT_HEADERS), nullptr) != 0)
        return false;

    const auto sec_offset = dos_header->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + nt_headers->FileHeader.SizeOfOptionalHeader;
    const auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(dll + sec_offset);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
    {
        const IMAGE_SECTION_HEADER section = sections[i];
        if (MyNtWriteVirtualMemory(handle, reinterpret_cast<LPVOID>(ptr + sec_offset + i * sizeof(IMAGE_SECTION_HEADER)), (PVOID)&section, sizeof(IMAGE_SECTION_HEADER), nullptr) != 0)
            return false;
    }
    return true;
}

// map_sections 函数保持不变
bool map_sections(HANDLE handle, const char *dll, const uintptr_t ptr, const IMAGE_NT_HEADERS *nt_headers)
{
    const auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
        reinterpret_cast<const char *>(&nt_headers->FileHeader) + sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
    {
        const IMAGE_SECTION_HEADER section = sections[i];
        if (MyNtWriteVirtualMemory(handle, reinterpret_cast<LPVOID>(ptr + section.VirtualAddress), (PVOID)(dll + section.PointerToRawData), section.SizeOfRawData, nullptr) != 0)
            return false;
    }
    return true;
}

c_manual_mapper::c_manual_mapper(HANDLE process)
{
    this->process = process;
}

c_manual_mapper::~c_manual_mapper()
{
    MyNtClose(this->process);
}

t_mapped_library *c_manual_mapper::manual_map(char *dll) const
{
    const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(dll);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "[!] invalid DOS header!" << std::endl;
        return nullptr;
    }
    const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(dll + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "[!] invalid NT headers!" << std::endl;
        return nullptr;
    }

    // --- 变量声明区 ---
    // MOVED: 将所有变量声明移到函数顶部以修复 goto 错误
    HANDLE hDllSection = NULL, hStubSection = NULL, hShellcodeSection = NULL;
    PVOID dll_buffer = nullptr, stub_buffer = nullptr, shellcode_buffer = nullptr;
    t_loader_stub stub; // 声明但未初始化
    HANDLE hThread = NULL;

    dll_buffer = allocate_memory_via_section(this->process, nt_headers->OptionalHeader.SizeOfImage, hDllSection);
    if (!dll_buffer)
    {
        std::cerr << "[!] DLL memory allocation via section mapping failed!" << std::endl;
        return nullptr;
    }
    std::cout << "[*] allocated DLL memory at 0x" << std::hex << dll_buffer << std::dec << std::endl;

    base_relocate(dll, reinterpret_cast<uintptr_t>(dll_buffer), nt_headers);

    if (!write_dll_header(this->process, dll, reinterpret_cast<uintptr_t>(dll_buffer), dos_header) ||
        !map_sections(this->process, dll, reinterpret_cast<uintptr_t>(dll_buffer), nt_headers))
    {
        std::cerr << "[!] Failed to write DLL headers or map sections!" << std::endl;
        goto cleanup;
    }
    std::cout << "[*] wrote DLL header and mapped sections" << std::endl;

    // CHANGED: 现在是赋值，而不是带初始化的声明
    stub = {
        .load_library_ptr = reinterpret_cast<void *>(LoadLibraryA),
        .get_proc_address_ptr = reinterpret_cast<void *>(GetProcAddress),
        .dll_base = dll_buffer,
        .iat_resolve_mode = IATLoadLibrary,
    };

    stub_buffer = allocate_memory_via_section(this->process, sizeof(t_loader_stub), hStubSection);
    if (!stub_buffer || MyNtWriteVirtualMemory(this->process, stub_buffer, (PVOID)&stub, sizeof(t_loader_stub), nullptr) != 0)
    {
        std::cerr << "[!] Stub buffer allocation/writing failed!" << std::endl;
        goto cleanup;
    }
    std::cout << "[*] wrote stub buffer" << std::endl;

    shellcode_buffer = allocate_memory_via_section(this->process, SHELLCODE_BUFFER_SIZE, hShellcodeSection);
    if (!shellcode_buffer || MyNtWriteVirtualMemory(this->process, shellcode_buffer, reinterpret_cast<PVOID>(&loader_stub), SHELLCODE_BUFFER_SIZE, nullptr) != 0)
    {
        std::cerr << "[!] Shellcode buffer allocation/writing failed!" << std::endl;
        goto cleanup;
    }
    std::cout << "[*] wrote shellcode" << std::endl;

    hThread = CreateRemoteThread(this->process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode_buffer), stub_buffer, 0, nullptr);
    if (!hThread)
    {
        std::cerr << "[!] CreateRemoteThread failed! Error: " << GetLastError() << std::endl;
        goto cleanup;
    }
    std::cout << "[*] created remote thread running shellcode" << std::endl;
    CloseHandle(hThread);

    MyNtClose(hDllSection);
    MyNtClose(hStubSection);
    MyNtClose(hShellcodeSection);

    return new t_mapped_library{.base_address = reinterpret_cast<uintptr_t>(dll_buffer)};

cleanup:
    std::cerr << "[!] An error occurred. Cleaning up..." << std::endl;
    if (shellcode_buffer)
        MyNtUnmapViewOfSection(this->process, shellcode_buffer);
    if (stub_buffer)
        MyNtUnmapViewOfSection(this->process, stub_buffer);
    if (dll_buffer)
        MyNtUnmapViewOfSection(this->process, dll_buffer);

    if (hShellcodeSection)
        MyNtClose(hShellcodeSection);
    if (hStubSection)
        MyNtClose(hStubSection);
    if (hDllSection)
        MyNtClose(hDllSection);

    return nullptr;
}

bool manual_map(DWORD process_id, char *dll)
{
    HANDLE process_handle = MyOpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        process_id);

    if (!process_handle)
    {
        std::cerr << "[!] MyOpenProcess failed!" << std::endl;
        return false;
    }
    std::cout << "[+] MyOpenProcess successfully returned a handle: " << process_handle << std::endl;

    const c_manual_mapper mapper(process_handle);
    t_mapped_library *library = mapper.manual_map(dll);
    if (library)
    {
        free(library);
    }
    return library != nullptr;
}

#ifdef _MSC_VER
#pragma optimize("", off)
#pragma runtime_checks("", off)
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((optimize("O0")))
__attribute__((noinline))
#endif
void loader_stub(const t_loader_stub *stub)
{
    const auto stub_dll_base_ptr = reinterpret_cast<uintptr_t>(stub->dll_base);

    const auto dos_header = static_cast<IMAGE_DOS_HEADER *>(stub->dll_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS *>(stub_dll_base_ptr + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        return;

    const auto LoadLibraryA_ = reinterpret_cast<t_load_library>(stub->load_library_ptr);
    const auto GetProcAddress_ = reinterpret_cast<t_get_proc_address>(stub->get_proc_address_ptr);

    if (stub->iat_resolve_mode == IATLoadLibrary && nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        auto import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(
            stub_dll_base_ptr + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (import_descriptor->Name)
        {
            HINSTANCE import_dll = LoadLibraryA_(reinterpret_cast<char *>(stub_dll_base_ptr + import_descriptor->Name));

            const auto original_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                stub_dll_base_ptr + (import_descriptor->OriginalFirstThunk
                                         ? import_descriptor->OriginalFirstThunk
                                         : import_descriptor->FirstThunk));
            const auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                stub_dll_base_ptr + import_descriptor->FirstThunk);
            int i = 0;

            while (original_first_thunk[i].u1.AddressOfData)
            {
                const ULONGLONG ordinal = original_first_thunk[i].u1.Ordinal;
                if (IMAGE_SNAP_BY_ORDINAL(ordinal))
                {
                    first_thunk[i].u1.Function = reinterpret_cast<ULONG_PTR>(GetProcAddress_(
                        import_dll, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(ordinal))));
                }
                else
                {
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

    if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0)
    {
        const auto tls_directory = reinterpret_cast<IMAGE_TLS_DIRECTORY *>(
            stub_dll_base_ptr + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto tls_callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(tls_directory->AddressOfCallBacks);
        while (*tls_callbacks)
        {
            (*tls_callbacks)(static_cast<PVOID>(stub->dll_base), DLL_PROCESS_ATTACH, nullptr);
            tls_callbacks++;
        }
    }

    reinterpret_cast<t_dll_main>(reinterpret_cast<uintptr_t>(stub->dll_base) + nt_headers->OptionalHeader.AddressOfEntryPoint)(static_cast<HINSTANCE>(stub->dll_base), DLL_PROCESS_ATTACH,
                                                                                                                               nullptr);
}
#ifdef _MSC_VER
#pragma optimize("", on)
#pragma runtime_checks("", restore)
#endif