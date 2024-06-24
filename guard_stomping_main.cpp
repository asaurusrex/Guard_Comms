/*THISE CODE DEMOES GUARD STOMPING TECHNIQUE*/
/*WRITTEN BY ASAURUSREX*/
#include <windows.h>
#include <vector>
#include <string>
#include <iostream>

using namespace std;


int main()
{
	//NOTE: THIS IS NOT OPSEC SAFE, JUST FOR DEMO PURPOSES
	//use DLL load to load module:
	int error;
	HINSTANCE hDLL = LoadLibraryW(L"Process_List.dll");
	error = GetLastError();
	if (hDLL != NULL)
	{
		wprintf(L"Successfully loaded library!\n");
	}
	else
	{
		wprintf(L"Unsuccessful library load, error is %d\n", error);
		exit(-1);
	}
	//Get address of our exported function
	FARPROC hAddress = GetProcAddress(hDLL, "ExportedFunction");

	//use CreateThread on the address of ExportedFunction
	HANDLE hThread;
	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hAddress, NULL, 0, NULL);
	

	//wait for thread to finish
	WaitForSingleObject(hThread, INFINITE);
	//unload our module
	FreeLibrary(hDLL);

	MEMORY_BASIC_INFORMATION mbi;
	ZeroMemory(&mbi, sizeof(mbi));
	
	//example of way you could do this with heap
	//wchar_t* heapAddress = (wchar_t*)malloc(2000000);
	//LPVOID heapAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2000000);
	
	//for wide chars:
	//hard coding is not necessarily best practice
	std::vector<BYTE> header = { 0x48, 0x00, 0x45, 0x00, 0x41, 0x00, 0x44, 0x00, 0x45, 0x00, 0x52, 0x00, 0x42, 0x00, 0x59, 0x00, 0x54, 0x00, 0x45, 0x00, 0x53 };  // HEADERBYTES
	std::vector<BYTE> footer = { 0x46, 0x00, 0x4F, 0x00, 0x4F, 0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x42, 0x00, 0x59, 0x00, 0x54, 0x00, 0x45, 0x00, 0x53 };  // FOOTERBYTES

	//can add extra headers/footers here:

	for (PBYTE baseAddress = nullptr;
		VirtualQueryEx(GetCurrentProcess(), baseAddress, &mbi, sizeof(mbi));
		baseAddress += mbi.RegionSize)
	{

		// Check if the region is committed and has PAGE_GUARD protection
		if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) && (mbi.Protect & PAGE_READWRITE)) //make sure readwrite and page guard protections
		{

			std::cout << "Guarded memory region found at: "
				<< static_cast<void*>(mbi.BaseAddress)
				<< " Size: " << mbi.RegionSize << " bytes"
				<< " Protection: " << mbi.Protect << "\n" << std::endl;

			DWORD oldprotect = 0;
			//printf("Found memory address at %X\n", mbi.BaseAddress);
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldprotect);

			wchar_t info[250000]; //don't go much past this limit on the stack, might risk badness

			SIZE_T bytesRead = 0;
			//ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, (LPVOID)info, mbi.RegionSize, &bytesRead);
			ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, (LPVOID)info, mbi.RegionSize, &bytesRead);
			printf("Bytes read: %d\n", bytesRead);
			for (size_t i = 0; i < bytesRead - header.size() + 1; ++i)
			{
				if (memcmp(info + i, header.data(), header.size()) == 0)
				{
					// Found the pattern
					
					//do something with the data

					wprintf(L"\n%ls\n", info);


					//overwrite the virtual memory with random zeroes, and then free it, and free wchar blocks
					//use memset to overwrite:
					memset(info, 0, mbi.RegionSize);
					memset(mbi.BaseAddress, 0, mbi.RegionSize);
					VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE | PAGE_GUARD, &oldprotect);
				}

				else
				{
					//reset memory region for info, still looking for our data
					memset(info, 0, mbi.RegionSize);
					VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE | PAGE_GUARD, &oldprotect);

				}
			}

		}

	}
	
	return 0;
}