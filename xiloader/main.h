#ifndef __EDENMAIN_H_INCLUDED__
#define __EDENMAIN_H_INCLUDED__

#pragma once

#ifdef EDENMAIN_EXPORTS
#define EDENMAIN_API __declspec(dllexport)
#else
#define EDENMAIN_API __declspec(dllimport)
#endif

#include "detours/detours.h"

#include <string>
#include "pch.h"

#define EDEN_VERSION	"00.01.04"

#define EDEN_CODE		"TESTKEY1"

typedef std::string string_t;

//extern "C" EDENMAIN_API 
const char* GetLauncherVersion(void);
//extern "C" EDENMAIN_API int __cdecl XiLoaderMain(int argc, char* argv[]);









//BOOL APIENTRY DllMain(HMODULE hModule,
//    DWORD  ul_reason_for_call,
//    LPVOID lpReserved
//)
//{
//    switch (ul_reason_for_call)
//    {
//    case DLL_PROCESS_ATTACH:
//    case DLL_THREAD_ATTACH:
//    case DLL_THREAD_DETACH:
//    case DLL_PROCESS_DETACH:
//        break;
//    }
//    return TRUE;
//}

#endif
