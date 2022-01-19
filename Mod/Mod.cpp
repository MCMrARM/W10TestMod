#include "pch.h"
#include "Mod.h"
#include <detours.h>
#include <string>
#include <fstream>
#include <Shlobj.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")

std::wstring acFolderPath;
std::wofstream modLog;

std::string(*Common$getGameVersionStringNet)();
std::string _Common$getGameVersionStringNet() {
    return Common$getGameVersionStringNet() + "mod";
}

void ModAttach() {
    PWSTR pAppDataPath;
    SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &pAppDataPath);
    acFolderPath = pAppDataPath;
    CoTaskMemFree(pAppDataPath);

    modLog.open(acFolderPath + L"\\ModLog.txt");
    UINT_PTR offset = (UINT_PTR)GetModuleHandle(L"Minecraft.Windows.exe");
    modLog << "offset = " << std::hex << offset << std::endl;

    (void*&)Common$getGameVersionStringNet = (void*) (offset - 0x140000000 + 0x14162C220);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Common$getGameVersionStringNet, _Common$getGameVersionStringNet);
    DetourTransactionCommit();
}

void ModDetach() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Common$getGameVersionStringNet, _Common$getGameVersionStringNet);
    DetourTransactionCommit();
}