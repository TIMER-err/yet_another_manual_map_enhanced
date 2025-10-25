#ifndef YET_ANOTHER_MANUAL_MAP_INJECTOR_H
#define YET_ANOTHER_MANUAL_MAP_INJECTOR_H
// #define MANUAL_MAP_DEBUG
#include <unordered_map>
#include <Windows.h>
#include <cstdint>

enum e_iat_resolver
{
    IATLoadLibrary,
    IATManualMap,
};

typedef struct s_loader_stub
{
    void *load_library_ptr;
    void *get_proc_address_ptr;
    void *dll_base;

    e_iat_resolver iat_resolve_mode;
} t_loader_stub;

typedef struct s_mapped_library
{
    uintptr_t base_address;
    std::unordered_map<std::string, uintptr_t> exports;
    std::unordered_map<WORD, uintptr_t> ordinal_exports;
} t_mapped_library;

class c_manual_mapper
{
    HANDLE process;
    std::unordered_map<std::string, s_mapped_library> libraries;

public:
    explicit c_manual_mapper(HANDLE process);
    ~c_manual_mapper();
    t_mapped_library *manual_map(char *dll) const;
};

typedef HMODULE(WINAPI *t_load_library)(LPCSTR lpLibFileName);
typedef FARPROC(WINAPI *t_get_proc_address)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL(WINAPI *t_dll_main)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef HMODULE(WINAPI *t_get_module_handle)(LPCSTR lpModuleName);

void loader_stub(const t_loader_stub *stub);
bool manual_map(DWORD process_id, char *dll);
#endif // YET_ANOTHER_MANUAL_MAP_INJECTOR_H
