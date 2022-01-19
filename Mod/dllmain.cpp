#include "pch.h"
#include <detours.h>
#include "Mod.h"

BOOL APIENTRY DllMain(HMODULE /* hModule */, DWORD dwReason, LPVOID /* lpReserved */)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        ModAttach();
    } else if (dwReason == DLL_PROCESS_DETACH) {
        ModDetach();
    }
    return TRUE;
}
