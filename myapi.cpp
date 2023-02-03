/*
 * Title:  myapi.cpp
 * Author: Shuichiro Endo
 */

#include <stdio.h>
#include <string.h>
#include <Windows.h>

#include "struct.h"
#include "winapi.h"
#include "myapi.h"

#define _DEBUG

HMODULE myGetModuleHandleW(wchar_t * lpModuleName)
{
#ifdef _WIN64
	PPEB64 pPEB = (PPEB64)__readgsqword(0x60);
#endif
//#ifdef _X86
//	PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
//#endif	

	if(lpModuleName == NULL){
		return (HMODULE)(pPEB->ImageBaseAddress);
	}
	
	PPEB_LDR_DATA Ldr = pPEB->Ldr;
	PLIST_ENTRY ModuleList = &Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pStartListEntry = ModuleList->Flink;
	
	for(PLIST_ENTRY pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink){
		PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pListEntry - sizeof(LIST_ENTRY));
		
		if(_wcsicmp((wchar_t *)pLdrDataTableEntry->BaseDllName.Buffer, lpModuleName) == 0){	
			return (HMODULE)pLdrDataTableEntry->DllBase;
		}
	}
	
	return NULL;
}


FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	HMODULE pBaseAddress = hModule;	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pBaseAddress + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	
	if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0){
		return NULL;
	}

	// search .rdata section header
	SIZE_T rdataAddress = 0;
	SIZE_T rdataSize = 0;
	for(int i = 0; i < pFileHeader->NumberOfSections; i++){
		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pBaseAddress + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		
		if(strncmp((char *)pSectionHeader->Name, ".rdata", strlen(".rdata")) == 0){
			rdataAddress = (SIZE_T)((LPBYTE)pBaseAddress + pSectionHeader->VirtualAddress);
			rdataSize = pSectionHeader->Misc.VirtualSize;
		}
	}
	
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pBaseAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD numberOfNames = pExportDirectory->NumberOfNames;
	DWORD *AddressOfNames = (DWORD *)((LPBYTE)pBaseAddress + pExportDirectory->AddressOfNames);
	WORD *AddressOfNameOrdinals = (WORD *)((LPBYTE)pBaseAddress + pExportDirectory->AddressOfNameOrdinals);
	DWORD *AddressOfFunctions = (DWORD *)((LPBYTE)pBaseAddress + pExportDirectory->AddressOfFunctions);
	
	wchar_t strKernel32[] = {L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0', 0x0};
	char strLoadLibraryA[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0};
	_LoadLibraryA pLoadLibraryA = NULL;

	LPSTR functionName = NULL;
	WORD ordinal = 0;
	DWORD base = 0;
	DWORD rva = 0;
	char *forwarder = NULL;
	char tmp[1000] = {0};
	char *token = NULL;
	char dname[1000] = {0};
	char *fname = NULL;
	FARPROC pFunctionAddress = NULL;
	
	if(((DWORD_PTR)lpProcName >> 16) == 0){	// ordinal
		ordinal = (WORD)lpProcName & 0xFFFF;
		base = pExportDirectory->Base;
		rva = AddressOfFunctions[ordinal - base];
		
		if(ordinal < base || ordinal >= base + pExportDirectory->NumberOfFunctions){
			return NULL;
		}
		
		pFunctionAddress = (FARPROC)((LPBYTE)pBaseAddress + rva);
		
		return pFunctionAddress;
	}else{
		for(DWORD i=0; i<numberOfNames; i++){
			functionName = (LPSTR)((LPBYTE)pBaseAddress + AddressOfNames[i]);
			ordinal = AddressOfNameOrdinals[i];
			rva = AddressOfFunctions[ordinal];
			
			if(strncmp(functionName, lpProcName, strlen(lpProcName)) == 0){
				forwarder = (char *)((LPBYTE)pBaseAddress + rva);

				// check address
				if((SIZE_T)forwarder >= rdataAddress && (SIZE_T)forwarder <= rdataAddress + rdataSize){
					if(strstr(forwarder, ".") != NULL){	// Forwarder
						memcpy(tmp, forwarder, strlen(forwarder));
						token = strtok(tmp, ".");
						sprintf(dname, "%s.dll", token);
					
						while(token != NULL){
							token = strtok(NULL, ".");
							if(token != NULL){
								fname = token;
							}
						}
#ifdef _DEBUG
//						printf("[I] dname:%s fname:%s\n", dname, fname);
#endif
						pLoadLibraryA = (_LoadLibraryA)myGetProcAddress(myGetModuleHandleW(strKernel32), strLoadLibraryA);
						if(pLoadLibraryA != NULL){
							pFunctionAddress = myGetProcAddress(pLoadLibraryA(dname), fname);
						}else{
							return NULL;
						}
						
						if(pFunctionAddress != NULL){
							return pFunctionAddress;
						}else{
							pFunctionAddress = (FARPROC)((LPBYTE)pBaseAddress + rva);
							
							return pFunctionAddress;
						}
					}else{
						
						pFunctionAddress = (FARPROC)((LPBYTE)pBaseAddress + rva);
						
						return pFunctionAddress;
					}
				}else{
					pFunctionAddress = (FARPROC)((LPBYTE)pBaseAddress + rva);
					
					return pFunctionAddress;
				}
			}
		}
	}
	
	return NULL;
}


FARPROC myGetFunctionAddress(HMODULE hModule, LPSTR lpProcName)
{
	HMODULE pBaseAddress = hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pBaseAddress + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0){
		return NULL;
	}
	
	// search .rdata section header
	SIZE_T rdataAddress = 0;
	SIZE_T rdataSize = 0;
	for(int i = 0; i < pFileHeader->NumberOfSections; i++){
		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pBaseAddress + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		
		if(strncmp((char *)pSectionHeader->Name, ".rdata", strlen(".rdata")) == 0){
			rdataAddress = (SIZE_T)((LPBYTE)pBaseAddress + pSectionHeader->VirtualAddress);
			rdataSize = pSectionHeader->Misc.VirtualSize;
		}
	}

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pBaseAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD numberOfNames = pExportDirectory->NumberOfNames;
	DWORD *AddressOfNames = (DWORD *)((LPBYTE)pBaseAddress + pExportDirectory->AddressOfNames);
	WORD *AddressOfNameOrdinals = (WORD *)((LPBYTE)pBaseAddress + pExportDirectory->AddressOfNameOrdinals);
	DWORD *AddressOfFunctions = (DWORD *)((LPBYTE)pBaseAddress + pExportDirectory->AddressOfFunctions);
	
	wchar_t strKernel32[] = {L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0', 0x0};
	char strLoadLibraryA[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0};
	_LoadLibraryA pLoadLibraryA = NULL;
	
	LPSTR functionName = NULL;
	WORD ordinal = 0;
	DWORD rva = 0;
	char *forwarder = NULL;
	char tmp[1000] = {0};
	char *token = NULL;
	char dname[1000] = {0};
	char *fname = NULL;
	FARPROC pFunctionAddress = NULL;

	for(DWORD i=0; i<numberOfNames; i++){
		functionName = (LPSTR)((LPBYTE)pBaseAddress + AddressOfNames[i]);
		ordinal = AddressOfNameOrdinals[i];
		rva = AddressOfFunctions[ordinal];
		
		if(strncmp(functionName, lpProcName, strlen(lpProcName)) == 0){
			forwarder = (char *)((LPBYTE)pBaseAddress + rva);

			// check address
			if((SIZE_T)forwarder >= rdataAddress && (SIZE_T)forwarder <= rdataAddress + rdataSize){
				if(strstr(forwarder, ".") != NULL){	// Forwarder
					memcpy(tmp, forwarder, strlen(forwarder));
					token = strtok(tmp, ".");
					sprintf(dname, "%s.dll", token);
				
					while(token != NULL){
						token = strtok(NULL, ".");
						if(token != NULL){
							fname = token;
						}
					}
#ifdef _DEBUG
//					printf("[I] dname:%s fname:%s\n", dname, fname);
#endif
					pLoadLibraryA = (_LoadLibraryA)myGetFunctionAddress(myGetModuleHandleW(strKernel32), strLoadLibraryA);
					if(pLoadLibraryA != NULL){
						pFunctionAddress = myGetFunctionAddress(pLoadLibraryA(dname), fname);
					}else{
						return NULL;
					}
					
					if(pFunctionAddress != NULL){
						return pFunctionAddress;
					}else{
						return (FARPROC)((LPBYTE)pBaseAddress + rva);
					}
				}else{
					return (FARPROC)((LPBYTE)pBaseAddress + rva);
				}
			}else{
				return (FARPROC)((LPBYTE)pBaseAddress + rva);
			}
		}
	}

	return NULL;
}


FARPROC myGetFunctionAddressByOrdinal(HMODULE hModule, WORD ordinal)
{
	HMODULE pBaseAddress = hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pBaseAddress + pDosHeader->e_lfanew);

	if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0){
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)pBaseAddress + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD base = pExportDirectory->Base;
	DWORD *AddressOfFunctions = (DWORD *)((LPBYTE)pBaseAddress + pExportDirectory->AddressOfFunctions);
	DWORD rva = AddressOfFunctions[ordinal - base];

	return (FARPROC)((LPBYTE)pBaseAddress + rva);
}


HMODULE myLoadDll(unsigned char dllData[], MANUAL_LOAD_DLL list[])
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_DATA_DIRECTORY pImportDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;	
	HMODULE pAllocAddress = NULL;
	
	wchar_t strKernel32[] = {L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0', 0x0};
	wchar_t strNtdll[] = {L'N', L'T', L'D', L'L', L'L', L'.', L'D', L'L', L'L', L'\0', 0x0};

	char strLoadLibraryA[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0};
	_LoadLibraryA pLoadLibraryA = (_LoadLibraryA)myGetProcAddress(myGetModuleHandleW(strKernel32), strLoadLibraryA);
	
	char strGetProcAddress[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0};
	_GetProcAddress pGetProcAddress = (_GetProcAddress)myGetProcAddress(myGetModuleHandleW(strKernel32), strGetProcAddress);

	char strVirtualAlloc[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0x0};
	_VirtualAlloc pVirtualAlloc = (_VirtualAlloc)myGetProcAddress(myGetModuleHandleW(strKernel32), strVirtualAlloc);

	char strVirtualProtect[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x0};
	_VirtualProtect pVirtualProtect = (_VirtualProtect)myGetProcAddress(myGetModuleHandleW(strKernel32), strVirtualProtect);
	
	char strRtlCopyMemory[] = {'R', 't', 'l', 'C', 'o', 'p', 'y', 'M', 'e', 'm', 'o', 'r', 'y', 0x0};
	_RtlCopyMemory pRtlCopyMemory = (_RtlCopyMemory)myGetProcAddress(myGetModuleHandleW(strNtdll), strRtlCopyMemory);
	
#ifdef _DEBUG
//	printf("[I] pLoadLibraryA:%#zx\n", pLoadLibraryA);
//	printf("[I] pGetProcAddress:%#zx\n", pGetProcAddress);
//	printf("[I] pVirtualAlloc:%#zx\n", pVirtualAlloc);
//	printf("[I] pVirtualProtect:%#zx\n", pVirtualProtect);
//	printf("[I] pRtlCopyMemory:%#zx\n", pRtlCopyMemory);
#endif
	
		
#ifdef _DEBUG
	printf("[I] Check dll data.\n");
#endif
	pDosHeader = (PIMAGE_DOS_HEADER)dllData;	
	if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE){
#ifdef _DEBUG
		printf("[E] Invalid dos format.\n");
#endif
		return NULL;
	}

	pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)dllData + pDosHeader->e_lfanew);
	if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE){
#ifdef _DEBUG
		printf("[E] Invalid pe format.\n");
#endif
		return NULL;
	}

	pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
	if(!(pFileHeader->Characteristics & IMAGE_FILE_DLL)){
#ifdef _DEBUG
		printf("[E] Invalid dll data.\n");
#endif
		return NULL;
	}

	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
	if(pOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC){
#ifdef _DEBUG
		printf("[E] Invalid architecture.");
#endif
		return NULL;
	}


#ifdef _DEBUG
	printf("[I] Allocate memory.\n");
#endif
	pAllocAddress = (HMODULE)pVirtualAlloc(NULL, pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(pAllocAddress == NULL){
#ifdef _DEBUG
		printf("[E] Unable to allocate memory.\n");
#endif
		return NULL;
	}
#ifdef _DEBUG
	printf("[I] Allocated memory. address:%#zx size:%#zx\n", (LPVOID)pAllocAddress, pOptionalHeader->SizeOfImage);
#endif


	SIZE_T beforeImageBase = (SIZE_T)pOptionalHeader->ImageBase;
	pOptionalHeader->ImageBase = (SIZE_T)pAllocAddress;
#ifdef _DEBUG
	printf("[I] Fix ImageBase before:%#zx -> after:%#zx\n", (LPVOID)beforeImageBase, (LPVOID)pOptionalHeader->ImageBase);
#endif


#ifdef _DEBUG
	printf("[I] Fix import address table.\n");
#endif
	pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)dllData + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;
	pImportDirectory = (PIMAGE_DATA_DIRECTORY)&pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	DWORD VirtualAddress = 0;
	DWORD VirtualSize = 0;
	DWORD PointerToRawData = 0;	
	DWORD SizeOfRawData = 0;
	DWORD d = 0;
	
	for(int i = 0; i < pFileHeader->NumberOfSections; i++){
		VirtualAddress = (DWORD)pSectionHeader[i].VirtualAddress;
		VirtualSize = (DWORD)pSectionHeader[i].Misc.VirtualSize;
		PointerToRawData = (DWORD)pSectionHeader[i].PointerToRawData;
		SizeOfRawData = (DWORD)pSectionHeader[i].SizeOfRawData;

		if((DWORD)pImportDirectory->VirtualAddress >= VirtualAddress && (DWORD)pImportDirectory->VirtualAddress <= (VirtualAddress+VirtualSize)){
			d = VirtualAddress - PointerToRawData;
#ifdef _DEBUG
			printf("[I] delta:%#zx\n", d);
#endif
			break;
		}
	}
		
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)dllData + (pImportDirectory->VirtualAddress - d));
	DWORD maxSize = pImportDirectory->Size;
	DWORD countSize = 0;
	LPSTR dllName = NULL;
	DWORD firstThunk = 0;
	DWORD originalFirstThunk = 0;
	DWORD offsetField = 0;
	DWORD offsetThunk = 0;
	HMODULE dllBaseAddress = NULL;
	PIMAGE_THUNK_DATA64 fieldThunk = NULL;
	PIMAGE_THUNK_DATA64 originalThunk = NULL;
	PIMAGE_IMPORT_BY_NAME byName = NULL;
	LPVOID address = NULL;
	LPSTR name = NULL;

	for(int i=0; countSize<maxSize; i++, countSize+=sizeof(IMAGE_IMPORT_DESCRIPTOR)){
		if(pImportDescriptor[i].OriginalFirstThunk == NULL && pImportDescriptor[i].FirstThunk == NULL){
			break;
		}
		
		dllName = (LPSTR)((LPBYTE)dllData + pImportDescriptor[i].Name - d);
#ifdef _DEBUG
		printf("[I] Import dll:%s\n", dllName);
#endif
		firstThunk = pImportDescriptor[i].FirstThunk;
		originalFirstThunk = pImportDescriptor[i].OriginalFirstThunk;
		if(originalFirstThunk == NULL){
			break;
		}
		offsetField = 0;
		offsetThunk = 0;

		dllBaseAddress = NULL;
		for(int j=0; list[j].dllBaseAddress != NULL; j++){
			if(!strncmp(list[j].dllName, dllName, strlen(dllName))){
#ifdef _DEBUG
				printf("[I] %s has already been loaded:%#zx.\n", list[j].dllName, list[j].dllBaseAddress);
#endif
				dllBaseAddress = list[j].dllBaseAddress;
			}
		}

		while(1){
			fieldThunk = (PIMAGE_THUNK_DATA64)&dllData[firstThunk + offsetField - d];
			originalThunk = (PIMAGE_THUNK_DATA64)&dllData[originalFirstThunk + offsetThunk - d];

			if(originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64){
				if(dllBaseAddress != NULL){
					address = (LPVOID)myGetFunctionAddressByOrdinal(dllBaseAddress, (WORD)(originalThunk->u1.Ordinal & 0xFFFF));
				}else{
					address = (LPVOID)pGetProcAddress(pLoadLibraryA(dllName), (char*)(originalThunk->u1.Ordinal & 0xFFFF));
				}
#ifdef _DEBUG
				printf("[I] ordinal:%#zx address:%#zx\n", originalThunk->u1.Ordinal & 0xFFFF, address);
#endif
				fieldThunk->u1.Function = (SIZE_T)address;
			}
			
			if(fieldThunk->u1.Function == NULL){
				break;
			}else if(fieldThunk->u1.Function == originalThunk->u1.Function){
				byName = (PIMAGE_IMPORT_BY_NAME)&dllData[fieldThunk->u1.AddressOfData - d];
				name = (LPSTR)byName->Name;
				if(dllBaseAddress != NULL){
					address = (LPVOID)myGetFunctionAddress(dllBaseAddress, name);
				}else{
					address = (LPVOID)pGetProcAddress(pLoadLibraryA(dllName), name);
				}
#ifdef _DEBUG
				printf("[I] functionname:%s address:%#zx\n", name, address);
#endif
				fieldThunk->u1.AddressOfData = (SIZE_T)address;
			}

			offsetField += sizeof(PIMAGE_THUNK_DATA64);
			offsetThunk += sizeof(PIMAGE_THUNK_DATA64);
		}
	}


#ifdef _DEBUG
	printf("[I] Write the dll data to the allocated memory.\n");	
	printf("[I] Writing headers. address:%#zx size:%#zx\n", pAllocAddress, pOptionalHeader->SizeOfHeaders);
#endif
	pRtlCopyMemory(pAllocAddress, (LPVOID)dllData, pOptionalHeader->SizeOfHeaders);

	SIZE_T size = 0;
	for(int i = 0; i < pFileHeader->NumberOfSections; i++){
		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)dllData + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		
		if(pSectionHeader->SizeOfRawData == 0){
			if(pSectionHeader->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA){
				size = pOptionalHeader->SizeOfInitializedData;
			}else if(pSectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA){
				size = pOptionalHeader->SizeOfUninitializedData;
			}
		}else{
			size = pSectionHeader->SizeOfRawData;
		}

#ifdef _DEBUG		
		printf("[I] Writing section data:%s address:%#zx size:%#zx\n",pSectionHeader->Name, (LPVOID)((LPBYTE)pAllocAddress + pSectionHeader->VirtualAddress), size);
#endif
		pRtlCopyMemory((LPVOID)((LPBYTE)pAllocAddress + pSectionHeader->VirtualAddress), (LPVOID)((LPBYTE)dllData + pSectionHeader->PointerToRawData), size);
	}


#ifdef _DEBUG
	printf("[I] Fix relocation section(.reloc).\n");
#endif
	SIZE_T delta = (SIZE_T)pAllocAddress - beforeImageBase;
#ifdef _DEBUG
	printf("[I] delta:%#zx\n", delta);
#endif
	LPSTR pRelocSectionName = NULL;
	DWORD relocAddress = 0;
	DWORD offset = 0;
	PIMAGE_DATA_DIRECTORY pRelocDataDirectory = NULL;
	PBASE_RELOCATION_BLOCK pBaseRelocationBlock = NULL;
	PBASE_RELOCATION_ENTRY pBaseRelocationEntry = NULL;
	DWORD entryCount = 0;
	DWORD field = 0;
	SIZE_T patch = 0; 

	if(delta){
		for(int i = 0; i < pFileHeader->NumberOfSections; i++){
			pRelocSectionName = (LPSTR)".reloc";

			if (memcmp(pSectionHeader[i].Name, pRelocSectionName, strlen(pRelocSectionName))){
				continue;
			}

			relocAddress = pSectionHeader[i].PointerToRawData;
			offset = 0;
			pRelocDataDirectory = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (offset < pRelocDataDirectory->Size) {
				pBaseRelocationBlock = (PBASE_RELOCATION_BLOCK)&dllData[relocAddress + offset];
				offset += sizeof(PBASE_RELOCATION_BLOCK);
				pBaseRelocationEntry = (PBASE_RELOCATION_ENTRY)&dllData[relocAddress + offset];
				entryCount = (pBaseRelocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
#ifdef _DEBUG
				printf("[I] entrycount:%d\n", entryCount);
#endif
				for (DWORD j = 0; j < entryCount; j++) {
					offset += sizeof(BASE_RELOCATION_ENTRY);
					if (pBaseRelocationEntry[j].Type == 0) {
						continue;
					}
					field = pBaseRelocationBlock->PageAddress + pBaseRelocationEntry[j].Offset;
					patch = 0;
					pRtlCopyMemory((LPVOID)&patch, (LPVOID)((LPBYTE)pAllocAddress + field), sizeof(SIZE_T));
					patch += delta;
#ifdef _DEBUG
					printf("[I] allocAddress+field:%#zx patch+delta:%#zx\n", (LPVOID)((LPBYTE)pAllocAddress + field), patch);
#endif
					pRtlCopyMemory((LPVOID)((LPBYTE)pAllocAddress + field), (LPVOID)&patch, sizeof(SIZE_T));
				}
			}
		}
	}


#ifdef _DEBUG
	printf("[I] Change the protection of the section data.\n");
#endif
	DWORD oldProtect;
	DWORD newProtect;
	BOOL executable;
	BOOL readable;
	BOOL writable;
	size = 0;
	DWORD alignment = pOptionalHeader->SectionAlignment;
	div_t res;

	for(int i=0; i<pFileHeader->NumberOfSections; i++){
		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pAllocAddress + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		executable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		readable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != 0;
		writable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
		
		if(executable){
			if(readable){
				if(writable){
					newProtect = PAGE_EXECUTE_READWRITE;		// 0x40
				}else{
					newProtect = PAGE_EXECUTE_READ;		// 0x20
				}
			}else{
				if(writable){
					newProtect = PAGE_EXECUTE_WRITECOPY;		// 0x80
				}else{
					newProtect = PAGE_EXECUTE;			// 0x10
				}
			}
		}else{
			if(readable){
				if(writable){
					newProtect = PAGE_READWRITE;			// 0x04
				}else{
					newProtect = PAGE_READONLY;			// 0x02
				}
			}else{
				if(writable){
					newProtect = PAGE_WRITECOPY;			// 0x08
				}else{
					newProtect = PAGE_NOACCESS;			// 0x01
				}
			}
		}

		if(pSectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_CACHED){
			newProtect |= PAGE_NOCACHE;	// 0x200
		}
		
		if(pSectionHeader->SizeOfRawData == 0){
			if(pSectionHeader->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA){
				size = pOptionalHeader->SizeOfInitializedData;
			}else if(pSectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA){
				size = pOptionalHeader->SizeOfUninitializedData;
			}
		}else{
			if(pSectionHeader->Misc.VirtualSize > pSectionHeader->SizeOfRawData){
				res = div((int)pSectionHeader->Misc.VirtualSize, (int)alignment);
				if(res.rem != 0){
					size = res.quot * alignment + alignment;
				}else{
					size = res.quot * alignment;
				}
			}else{
				res = div((int)pSectionHeader->SizeOfRawData, (int)alignment);
				if(res.rem != 0){
					size = res.quot * alignment + alignment;
				}else{
					size = res.quot * alignment;
				}
			}
		}
		
		if(pVirtualProtect((LPVOID)((LPBYTE)pAllocAddress + pSectionHeader->VirtualAddress), size, newProtect, &oldProtect) == 0){
#ifdef _DEBUG
			printf("[E] VirtualProtect error.\n");
#endif
			return NULL;
		}
		
#ifdef _DEBUG
		printf("[I] section data:%s address:%#zx size:%#zx oldProtect:%#zx newProtect:%#zx\n", pSectionHeader->Name, (LPVOID)((LPBYTE)pAllocAddress + pSectionHeader->VirtualAddress), size, oldProtect, newProtect);
#endif
	}


#ifdef _DEBUG
	printf("[I] Check tls callback.\n");
#endif

	PIMAGE_TLS_DIRECTORY pTLSDirectory;
	ULONGLONG *pCallbackArray;
	PIMAGE_TLS_CALLBACK pCallback;

	if(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0){
#ifdef _DEBUG
	printf("[I] Run tls callback.\n");
#endif
		pTLSDirectory = (PIMAGE_TLS_DIRECTORY)((LPBYTE)pAllocAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		pCallbackArray = &pTLSDirectory->AddressOfCallBacks;

		for(int i=0; pCallbackArray[i]!=NULL; i++){
			pCallback = (PIMAGE_TLS_CALLBACK)pCallbackArray[i];
			pCallback(pAllocAddress, DLL_PROCESS_ATTACH, NULL);
		}
	}


#ifdef _DEBUG
	printf("[I] Run dllmain.\n");
#endif
	_DLLMAIN pDllmain = (_DLLMAIN)((LPBYTE)pAllocAddress + pOptionalHeader->AddressOfEntryPoint);
	BOOL result = pDllmain((HINSTANCE)pAllocAddress, DLL_PROCESS_ATTACH, NULL);
	if(!result){
#ifdef _DEBUG
		printf("[E] dllmain error.\n");
#endif
		return NULL;
	}

	return pAllocAddress;
}


void myFreeDll(HMODULE hModule, MANUAL_LOAD_DLL list[])
{
	HMODULE pBaseAddress = hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pBaseAddress + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNtHeaders->OptionalHeader;
	BOOL result;
	
	wchar_t strKernel32[] = {L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', L'\0', 0x0};

	char strLoadLibraryA[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0};
	_LoadLibraryA pLoadLibraryA = (_LoadLibraryA)myGetProcAddress(myGetModuleHandleW(strKernel32), strLoadLibraryA);
	
	char strGetProcAddress[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0};
	_GetProcAddress pGetProcAddress = (_GetProcAddress)myGetProcAddress(myGetModuleHandleW(strKernel32), strGetProcAddress);
	
	char strGetModuleHandleA[] = {'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0x0};
	_GetModuleHandleA pGetModuleHandleA = (_GetModuleHandleA)myGetProcAddress(myGetModuleHandleW(strKernel32), strGetModuleHandleA);
	
	char strFreeLibrary[] = {'F', 'r', 'e', 'e', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 0x0};
	_FreeLibrary pFreeLibrary = (_FreeLibrary)myGetProcAddress(myGetModuleHandleW(strKernel32), strFreeLibrary);
	
	char strVirtualFree[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0x0};
	_VirtualFree pVirtualFree = (_VirtualFree)myGetProcAddress(myGetModuleHandleW(strKernel32), strVirtualFree);
	
	
#ifdef _DEBUG
	printf("[I] Check tls callback.\n");
#endif

	PIMAGE_TLS_DIRECTORY pTLSDirectory;
	ULONGLONG *pCallbackArray;
	PIMAGE_TLS_CALLBACK pCallback;

	if(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0){
#ifdef _DEBUG
	printf("[I] Run tls callback.\n");
#endif
		pTLSDirectory = (PIMAGE_TLS_DIRECTORY)((LPBYTE)pBaseAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		pCallbackArray = &pTLSDirectory->AddressOfCallBacks;

		for(int i=0; pCallbackArray[i]!=NULL; i++){
			pCallback = (PIMAGE_TLS_CALLBACK)pCallbackArray[i];
			pCallback(pBaseAddress, DLL_PROCESS_DETACH, NULL);
		}
	}
	
	
#ifdef _DEBUG
	printf("[I] Run dllmain.\n");
#endif
	_DLLMAIN pDllmain = (_DLLMAIN)((LPBYTE)pBaseAddress + pOptionalHeader->AddressOfEntryPoint);
	result = pDllmain((HINSTANCE)pBaseAddress, DLL_PROCESS_DETACH, NULL);
	if(!result){
#ifdef _DEBUG
		printf("[E] dllmain error.\n");
#endif
		return;
	}
	
	
#ifdef _DEBUG
	printf("[I] Free import library.\n");
#endif	
	
	PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pOptionalHeader->DataDirectory;
	PIMAGE_DATA_DIRECTORY pImportDirectory = (PIMAGE_DATA_DIRECTORY)&pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pBaseAddress + pImportDirectory->VirtualAddress);
	DWORD maxSize = pImportDirectory->Size;
	DWORD countSize = 0;
	LPSTR dllName = NULL;
	BOOL freeFlag = 1;

	for(int i=0; countSize<maxSize; i++, countSize+=sizeof(IMAGE_IMPORT_DESCRIPTOR)){
		if(pImportDescriptor[i].OriginalFirstThunk == NULL && pImportDescriptor[i].FirstThunk == NULL){
			break;
		}
		
		dllName = (LPSTR)((LPBYTE)pBaseAddress + pImportDescriptor[i].Name);
#ifdef _DEBUG
		printf("[I] Import dll:%s\n", dllName);
#endif
		freeFlag = 1;
		for(int j=0; list[j].dllBaseAddress != NULL; j++){
			if(!strncmp(list[j].dllName, dllName, strlen(dllName))){
				freeFlag = 0;
			}
		}

		if(freeFlag){
#ifdef _DEBUG
			printf("[I] Free %s\n", dllName);
#endif
			result = pFreeLibrary(pGetModuleHandleA(dllName));
			if(!result){
#ifdef _DEBUG
				printf("[E] FreeLibrary error.\n");
				return;
#endif
			}
		}
	}
	
	
#ifdef _DEBUG
	printf("[I] Free memory.\n");
#endif
	result = pVirtualFree(pBaseAddress, 0, MEM_RELEASE);
	if(!result){
#ifdef _DEBUG
		printf("[E] VirtualFree error.\n");
#endif
		return;
	}
	
	return;
}



