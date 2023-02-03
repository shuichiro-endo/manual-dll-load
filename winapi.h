/*
 * Title:  winapi.h
 * Author: Shuichiro Endo
 */

#pragma once

typedef HMODULE (WINAPI* _LoadLibraryA)(LPCSTR lpLibFileName);

typedef FARPROC (WINAPI* _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef LPVOID (WINAPI* _VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

typedef BOOL (WINAPI* _VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef void (WINAPI* _RtlCopyMemory)(void *Destination, const void *Source, size_t Length);

typedef BOOL (WINAPI* _DLLMAIN)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

typedef HMODULE (WINAPI* _GetModuleHandleA)(LPCSTR lpModuleName);

typedef BOOL (WINAPI* _FreeLibrary)(HMODULE hLibModule);

typedef BOOL (WINAPI* _VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);


