/*
 * Title:  myapi.h
 * Author: Shuichiro Endo
 */

#pragma once

HMODULE myGetModuleHandleW(wchar_t * lpModuleName);

FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName);

FARPROC myGetFunctionAddress(HMODULE hModule, LPSTR lpProcName);

FARPROC myGetFunctionAddressByOrdinal(HMODULE hModule, WORD ordinal);

typedef struct {
	char dllName[256] = "\0";
	HMODULE dllBaseAddress = NULL;
} MANUAL_LOAD_DLL, pMANUAL_LOAD_DLL;

HMODULE myLoadDll(unsigned char dllData[], MANUAL_LOAD_DLL list[]);

void myFreeDll(HMODULE hModule, MANUAL_LOAD_DLL list[]);

