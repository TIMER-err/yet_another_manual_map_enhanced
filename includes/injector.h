#ifndef YET_ANOTHER_MANUAL_MAP_INJECTOR_H
#define YET_ANOTHER_MANUAL_MAP_INJECTOR_H
// #define MANUAL_MAP_DEBUG
#include <Windows.h>

typedef struct s_loader_stub {
    void *load_library_ptr;
    void *get_proc_address_ptr;
    void *dll_base;
} t_loader_stub;

typedef HMODULE(*t_load_library)(LPCSTR lpLibFileName);
typedef FARPROC(*t_get_proc_address)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL(WINAPI *t_dll_main)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

void loader_stub(const t_loader_stub *stub);
bool manual_map(DWORD process_id, char *dll);
#endif //YET_ANOTHER_MANUAL_MAP_INJECTOR_H