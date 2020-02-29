/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

This file is part of DarkStar-server source code.

===========================================================================
*/

#include "pch.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "console.h"
#include "functions.h"
#include "network.h"
#include <intrin.h>

#include "main.h"

extern "C" EDENMAIN_API const char* GetLauncherVersion(void)
{
    return (const char*)EDEN_VERSION;
}

#include "defines.h"

#pragma intrinsic(_ReturnAddress)

/* Global Variables */
Language g_Language = Language::English; // The language of the loader to be used for polcore.
std::string g_ServerAddress = "play.edenxi.com"; // The server address to connect to.
std::string g_ServerPort = "51220"; // The server lobby server port to connect to.
std::string g_Email = ""; // The email provided during account creation.
std::string g_Username = ""; // The username being logged in with.
std::string g_Password = ""; // The password being logged in with.
std::string g_UniqueKey = ""; // The unique key given to the requested connection attempt.

/* Session Related Variables */
unsigned char g_SessionHash[16] = { 0 };

char* g_CharacterList = NULL; // Pointer to the character list data being sent from the server.
bool g_IsRunning = false; // Flag to determine if the network threads should hault.
bool g_Hide = false; // Determines whether or not to hide the console window after FFXI starts.

/* Hairpin Fix Variables */
DWORD g_NewServerAddress; // Hairpin server address to be overriden with.
DWORD g_HairpinReturnAddress; // Hairpin return address to allow the code cave to return properly.

/**
 * @brief Detour function definitions.
 */
extern "C"
{
    hostent* (WINAPI __stdcall* Real_gethostbyname)(const char* name) = gethostbyname;
}

/**
 * @brief Hairpin fix codecave.
 */
__declspec(naked) void HairpinFixCave(void)
{
    __asm mov eax, g_NewServerAddress
    __asm mov[edx + 0x012E90], eax
    __asm mov[edx], eax
    __asm jmp g_HairpinReturnAddress
}

extern "C"     int(WSAAPI * Real_send)(__in SOCKET s, __in_bcount(len) const char FAR * buf, __in int len, __in int flags) = send;

int WSAAPI Mine_send(__in SOCKET s, __in_bcount(len) const char FAR* buf, __in int len, __in int flags)
{
    const auto ret = _ReturnAddress();
    if (len == 0x98 && buf[8] == 0x26) { // always send server provided session hash in the first view socket outbound packet
        memcpy((BYTE*)(buf + 12), g_SessionHash, 16);
    }

    return Real_send(s, buf, len, flags);
}

/**
 * @brief Applies the hairpin fix modifications.
 *
 * @param lpParam       Thread param object.
 *
 * @return Non-important return.
 */
DWORD ApplyHairpinFixThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    do
    {
        /* Sleep until we find FFXiMain loaded.. */
        Sleep(100);
    } while (GetModuleHandleA("FFXiMain.dll") == NULL);

    /* Convert server address.. */
    network::ResolveHostname(g_ServerAddress.c_str(), &g_NewServerAddress);

    // Locate the main hairpin location..
    //
    // As of 07.08.2013:
    //      8B 82 902E0100        - mov eax, [edx+00012E90]
    //      89 02                 - mov [edx], eax <-- edit this

    auto hairpinAddress = (DWORD)functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x82\xFF\xFF\xFF\xFF\x89\x02\x8B\x0D", "xx????xxxx");
    if (hairpinAddress == 0)
    {
        console::output(color::error, "Failed to locate main hairpin hack address!");
        return 0;
    }

    // Locate zoning IP change address..
    // 
    // As of 07.08.2013
    //      74 08                 - je FFXiMain.dll+E5E72
    //      8B 0D 68322B03        - mov ecx, [FFXiMain.dll+463268]
    //      89 01                 - mov [ecx], eax <-- edit this
    //      8B 46 0C              - mov eax, [esi+0C]
    //      85 C0                 - test eax, eax

    auto zoneChangeAddress = (DWORD)functions::FindPattern("FFXiMain.dll", (BYTE*)"\x8B\x0D\xFF\xFF\xFF\xFF\x89\x01\x8B\x46", "xx????xxxx");
    if (zoneChangeAddress == 0)
    {
        console::output(color::error, "Failed to locate zone change hairpin address!");
        return 0;
    }

    /* Apply the hairpin fix.. */
    auto caveDest = ((int)HairpinFixCave - ((int)hairpinAddress)) - 5;
    g_HairpinReturnAddress = hairpinAddress + 0x08;

    *(BYTE*)(hairpinAddress + 0x00) = 0xE9; // jmp
    *(UINT*)(hairpinAddress + 0x01) = caveDest;
    *(BYTE*)(hairpinAddress + 0x05) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x06) = 0x90; // nop
    *(BYTE*)(hairpinAddress + 0x07) = 0x90; // nop

    /* Apply zone ip change patch.. */
    memset((LPVOID)(zoneChangeAddress + 0x06), 0x90, 2);

    console::output(color::success, "Hairpin fix applied!");
    return 0;
}

/**
 * @brief gethostbyname detour callback.
 *
 * @param name      The hostname to obtain information of.
 *
 * @return Hostname information object.
 */
hostent* __stdcall Mine_gethostbyname(const char* name)
{
    console::output(color::debug, "Resolving host: %s", name);

    if (!strcmp("ffxi00.pol.com", name))
        return Real_gethostbyname(g_ServerAddress.c_str());
    if (!strcmp("pp000.pol.com", name))
        return Real_gethostbyname("127.0.0.1");

    return Real_gethostbyname(name);
}

/**
 * @brief Locates the INET mutex function call inside of polcore.dll
 *
 * @return The pointer to the function call.
 */
inline DWORD FindINETMutex(void)
{
    const char* module = (g_Language == Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto result = (DWORD)functions::FindPattern(module, (BYTE*)"\x8B\x56\x2C\x8B\x46\x28\x8B\x4E\x24\x52\x50\x51", "xxxxxxxxxxxx");
    return (*(DWORD*)(result - 4) + (result));
}

/**
 * @brief Locates the PlayOnline connection object inside of polcore.dll
 *
 * @return Pointer to the pol connection object.
 */
inline DWORD FindPolConn(void)
{
    const char* module = (g_Language == Language::European) ? "polcoreeu.dll" : "polcore.dll";
    auto result = (DWORD)functions::FindPattern(module, (BYTE*)"\x81\xC6\x38\x03\x00\x00\x83\xC4\x04\x81\xFE", "xxxxxxxxxxx");
    return (*(DWORD*)(result - 10));
}

/**
 * @brief Locates the current character information block.
 *
 * @return Pointer to the character information table.
 */
inline LPVOID FindCharacters(void** commFuncs)
{
    LPVOID lpCharTable = NULL;
    memcpy(&lpCharTable, (char*)commFuncs[0xD3] + 31, sizeof(lpCharTable));
    return lpCharTable;
}

/**
 * @brief Main program entrypoint.
 *
 * @param argc      The count of arguments being passed to this application on launch.
 * @param argv      Pointer to array of argument data.
 *
 * @return 1 on error, 0 on success.
 */
extern "C" EDENMAIN_API int __cdecl XiLoaderMain(int argc, char* argv[])
{
    bool bUseHairpinFix = true; // always enable for now

    // check to make sure the filename is edenxi.exe (some disallowed tools only work on pol.exe)
    std::string filename(argv[0]);
    if (filename.substr(filename.size() - 10, filename.size()) != "edenxi.exe")
    {
        console::output(color::warning, "Warning: Using any bootloader not downloaded from edenxi.com is not allowed.");
        console::output(color::warning, "If you received this file from another source press CTRL + c to quit.");
        Sleep(30000);
        return 1;
    }

    /* Output the DarkStar banner.. */
    console::output(color::lightred, "===========================================================================");
    console::output(color::lightgreen, "DarkStar Boot Loader (c) 2020 DarkStar Team");
    console::output(color::lightgreen, "Modified for use with the Eden Server, Version %s", EDEN_VERSION);
    console::output(color::lightcyan, "Bugs: https://github.com/EdenServer/community/issues");
    console::output(color::lightcyan, "Discord: https://discord.gg/MWtDws8");
    console::output(color::lightcyan, "Website: https://www.edenxi.com");
    console::output(color::lightred, "===========================================================================");
    console::output(color::lightyelllow, "By connecting to Eden you agree to our terms and conditions.");
    console::output(color::lightyelllow, "Please read these on the server information section of our website.");
    console::output(color::lightred, "===========================================================================");

    /* Initialize Winsock */
    WSADATA wsaData = { 0 };
    auto ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0)
    {
        console::output(color::error, "Failed to initialize winsock, error code: %d", ret);
        return 1;
    }

    /* Initialize COM */
    auto hResult = CoInitialize(NULL);
    if (hResult != S_OK && hResult != S_FALSE)
    {
        /* Cleanup Winsock */
        WSACleanup();

        console::output(color::error, "Failed to initialize COM, error code: %d", hResult);
        return 1;
    }

    /* Attach detour for gethostbyname.. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourAttach(&(PVOID&)Real_send, Mine_send);
    if (DetourTransactionCommit() != NO_ERROR)
    {
        /* Cleanup COM and Winsock */
        CoUninitialize();
        WSACleanup();

        console::output(color::error, "Failed to detour function 'gethostbyname'. Cannot continue!");
        return 1;
    }

    /* Read Command Arguments */
    for (auto x = 1; x < argc; ++x)
    {
        /* Server Address Argument */
        if (!_strnicmp(argv[x], "--server", 8))
        {
            g_ServerAddress = argv[++x];
            continue;
        }

        /* Server Port Argument */
        if (!_strnicmp(argv[x], "--port", 6))
        {
            g_ServerPort = argv[++x];
            continue;
        }

        /* Username Argument */
        if (!_strnicmp(argv[x], "--user", 6))
        {
            g_Username = argv[++x];
            continue;
        }

        /* Password Argument */
        if (!_strnicmp(argv[x], "--pass", 6))
        {
            g_Password = argv[++x];
            continue;
        }

        /* Unique Key Argument */
        if (!_strnicmp(argv[x], "--ukey", 6))
        {
            g_UniqueKey = argv[++x];
            continue;
        }

        /* Language Argument */
        if (!_strnicmp(argv[x], "--lang", 6))
        {
            std::string language = argv[++x];

            if (!_strnicmp(language.c_str(), "JP", 2) || !_strnicmp(language.c_str(), "0", 1))
                g_Language = Language::Japanese;
            if (!_strnicmp(language.c_str(), "US", 2) || !_strnicmp(language.c_str(), "1", 1))
                g_Language = Language::English;
            if (!_strnicmp(language.c_str(), "EU", 2) || !_strnicmp(language.c_str(), "2", 1))
                g_Language = Language::European;

            continue;
        }

        /* Hairpin Argument */
        if (!_strnicmp(argv[x], "--hairpin", 9))
        {
            bUseHairpinFix = true;
            continue;
        }

        /* Hide Argument */
        if (!_strnicmp(argv[x], "--hide", 6))
        {
            g_Hide = true;
            continue;
        }

        console::output(color::warning, "Found unknown command argument: %s", argv[x]);
    }

    /* Attempt to resolve the server address.. */
    ULONG ulAddress = 0;
    if (network::ResolveHostname(g_ServerAddress.c_str(), &ulAddress, argv[0]))
    {
        g_ServerAddress = inet_ntoa(*((struct in_addr*) & ulAddress));

        /* Attempt to create socket to server..*/
        datasocket sock;
        if (network::CreateConnection(&sock, "54231"))
        {
            /* Attempt to verify the users account info.. */
            while (!network::VerifyAccount(&sock))
                Sleep(10);

            /* Start hairpin hack thread if required.. */
            if (bUseHairpinFix)
            {
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ApplyHairpinFixThread, NULL, 0, NULL);
            }

            /* Create listen servers.. */
            g_IsRunning = true;
            HANDLE hFFXiServer = CreateThread(NULL, 0, network::FFXiServer, &sock, 0, NULL);
            HANDLE hPolServer = CreateThread(NULL, 0, network::PolServer, NULL, 0, NULL);

            /* Attempt to create polcore instance..*/
            IPOLCoreCom* polcore = NULL;
            if (CoCreateInstance(CLSID_POLCoreCom[g_Language], NULL, 0x17, IID_IPOLCoreCom[g_Language], (LPVOID*)&polcore) != S_OK)
            {
                console::output(color::error, "Failed to initialize instance of polcore!");
            }
            else
            {
                /* Invoke the setup functions for polcore.. */
                polcore->SetAreaCode(g_Language);
                polcore->SetParamInit(GetModuleHandle(NULL), (LPSTR)" /game eAZcFcB -net 3");

                /* Obtain the common function table.. */
                void* (**lpCommandTable)(...);
                polcore->GetCommonFunctionTable((unsigned long**)&lpCommandTable);

                /* Invoke the inet mutex function.. */
                auto findMutex = (void* (*)(...))FindINETMutex();
                findMutex();

                /* Locate and prepare the pol connection.. */
                auto polConnection = (char*)FindPolConn();
                memset(polConnection, 0x00, 0x68);
                auto enc = (char*)malloc(0x1000);
                memset(enc, 0x00, 0x1000);
                memcpy(polConnection + 0x48, &enc, sizeof(char**));

                /* Locate the character storage buffer.. */
                g_CharacterList = (char*)FindCharacters((void**)lpCommandTable);

                /* Invoke the setup functions for polcore.. */
                lpCommandTable[POLFUNC_REGISTRY_LANG](g_Language);
                lpCommandTable[POLFUNC_FFXI_LANG](functions::GetRegistryPlayOnlineLanguage(g_Language));
                lpCommandTable[POLFUNC_REGISTRY_KEY](functions::GetRegistryPlayOnlineKey(g_Language));
                lpCommandTable[POLFUNC_INSTALL_FOLDER](functions::GetRegistryPlayOnlineInstallFolder(g_Language));
                lpCommandTable[POLFUNC_INET_MUTEX]();

                /* Attempt to create FFXi instance..*/
                IFFXiEntry* ffxi = NULL;
                if (CoCreateInstance(CLSID_FFXiEntry, NULL, 0x17, IID_IFFXiEntry, (LPVOID*)&ffxi) != S_OK)
                {
                    console::output(color::error, "Failed to initialize instance of FFxi!");
                }
                else
                {
                    /* Attempt to start Final Fantasy.. */
                    IUnknown* message = NULL;
                    console::hide();
                    ffxi->GameStart(polcore, &message);
                    console::show();
                    ffxi->Release();
                }

                /* Cleanup polcore object.. */
                if (polcore != NULL)
                    polcore->Release();
            }

            /* Cleanup threads.. */
            g_IsRunning = false;
            TerminateThread(hFFXiServer, 0);
            TerminateThread(hPolServer, 0);

            WaitForSingleObject(hFFXiServer, 1000);
            WaitForSingleObject(hPolServer, 1000);

            CloseHandle(hFFXiServer);
            CloseHandle(hPolServer);
        }
    }
    else
    {
        console::output(color::error, "Failed to resolve server hostname.");
    }

    /* Detach detour for gethostbyname. */
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_gethostbyname, Mine_gethostbyname);
    DetourTransactionCommit();

    /* Cleanup COM and Winsock */
    CoUninitialize();
    WSACleanup();

    console::output(color::error, "Closing...");
    Sleep(2000);

    return ERROR_SUCCESS;
}
