/*THISE CODE DEMOES GUARD COMMS TECHNIQUE*/
/*WRITTEN BY ASAURUSREX*/

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>

using namespace std;


int main()
{
	//use DLL load to load module:
	//NOTE: THIS IS NOT OPSEC SAFE, JUST FOR DEMO PURPOSES
	int error;
	HINSTANCE hDLL = LoadLibraryW(L"Process_Listing.dll");
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

	MEMORY_BASIC_INFORMATION mbi;
	ZeroMemory(&mbi, sizeof(mbi));
	//std::vector<BYTE> header = { 0x42, 0x45, 0x47, 0x49, 0x4e, 0x4d, 0x45, 0x53, 0x53, 0x41, 0x47, 0x45 }; this is for char vs wchar header


	//for wide chars:
	std::vector<BYTE> header = { 0x48, 0x00, 0x45, 0x00, 0x41, 0x00, 0x44, 0x00, 0x45, 0x00, 0x52, 0x00, 0x42, 0x00, 0x59, 0x00, 0x54, 0x00, 0x45, 0x00, 0x53 };  // HEADERBYTES
	std::vector<BYTE> footer = { 0x46, 0x00, 0x4F, 0x00, 0x4F, 0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x42, 0x00, 0x59, 0x00, 0x54, 0x00, 0x45, 0x00, 0x53 };  // FOOTERBYTES

	for (PBYTE baseAddress = nullptr;
		VirtualQueryEx(GetCurrentProcess(), baseAddress, &mbi, sizeof(mbi)); //can also use VirtualQuery here if sticking to local process, just showing this also works remote process
		baseAddress += mbi.RegionSize)
	{

		// Check if the region is committed and has PAGE_GUARD protection
		if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) && (mbi.Protect & PAGE_READWRITE)) //make sure readwrite and page guard protections
		{
			
			std::cout << "Guarded memory region found at: "
				<< static_cast<void*>(mbi.BaseAddress)
				<< " Size: " << mbi.RegionSize << " bytes"                                                                                                                                                  
				<< " Protection: " << mbi.Protect << "\n" << std::endl;
			
			DWORD oldprotect = PAGE_READWRITE | PAGE_GUARD;
			//printf("Found memory address at %X\n", mbi.BaseAddress);
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldprotect);
			
			wchar_t info[250000]; //don't go much past this limit on the stack, might risk badness
			
			SIZE_T bytesRead = 0;
			ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, (LPVOID)info, mbi.RegionSize, &bytesRead);
			printf("Bytes read: %d\n", bytesRead);
			for (size_t i = 0; i < bytesRead - header.size() + 1; ++i)
			{
				if (memcmp(info + i, header.data(), header.size()) == 0)
				{
					// Found the pattern
					wprintf(L"Found the header!\n\n");
					
					//do something with the data
					wprintf(L"\n%ls\n", info);
					
					//overwrite the virtual memory with random zeroes, and then free it, and free wchar blocks
					//use memset to overwrite:
					memset(mbi.BaseAddress, 0, mbi.RegionSize);
					
					//free the allocated memory for cleanup
					VirtualFree(mbi.BaseAddress, 0, MEM_RELEASE);
				}
				else
				{
					//reset memory region for info, still looking for our data
					memset(info, 0, mbi.RegionSize);
					VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE | PAGE_GUARD, &oldprotect);
				}
			}
			//unload our module
			FreeLibrary(hDLL);
			


		}

	}
	return 0;
}