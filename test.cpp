/*
 * Title:  test.cpp (sample)
 * Author: Shuichiro Endo
 */

#include <stdio.h>
#include <Windows.h>

#include "struct.h"
#include "winapi.h"
#include "myapi.h"

#include "test1dll.h"	// xxd -i test1.dll > test1dll.h
#include "test2dll.h"	// xxd -i test2.dll > test2dll.h

typedef int (* _func1)(int a);			// func1 function in test1.dll
typedef int (* _func2)(int b, int c);	// func2 function in test2.dll


int wmain(int argc, wchar_t *argv[])
{
	MANUAL_LOAD_DLL list[3];
	HMODULE address = NULL;

	// load test1.dll
	address = myLoadDll(test1_dll, list);	// unsigned char test1_dll[]
	if(address == NULL){
		printf("[E] test1_dll load error.\n");
		return -1;
	}
	strncpy(list[0].dllName, "test1.dll", strlen("test1.dll"));
	list[0].dllBaseAddress = address;

	// load test2.dll
	address = myLoadDll(test2_dll, list);	// unsigned char test2_dll[]
	if(address == NULL){
		printf("[E] test2_dll load error.\n");
		return -1;
	}
	strncpy(list[1].dllName, "test2.dll", strlen("test2.dll"));
	list[1].dllBaseAddress = address;


	// call func1 function in test1.dll
	_func1 pfunc1 = (_func1)myGetFunctionAddress(list[0].dllBaseAddress, "func1");
	int result_1 = pfunc1(10);

	// call func2 function in test2.dll
	_func2 pfunc2 = (_func2)myGetFunctionAddress(list[1].dllBaseAddress, "func2");
	int result_2 = pfunc2(10, 20);


	// free test2.dll
	myFreeDll(list[1].dllBaseAddress, list);
	strncpy(list[1].dllName, "\0", strlen("\0"));
	list[1].dllBaseAddress = NULL;

	// free test1.dll
	myFreeDll(list[0].dllBaseAddress, list);
	strncpy(list[0].dllName, "\0", strlen("\0"));
	list[0].dllBaseAddress = NULL;
	
	return 0;
}
