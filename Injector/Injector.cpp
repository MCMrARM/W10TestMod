#include <iostream>
#include <cstring>
#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>

DWORD FindMinecraftPID() {
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		throw std::runtime_error("CreateToolhelp32Snapshot failed");
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe))
		throw std::runtime_error("Process32First failed");
	DWORD ret = 0;
	do {
		if (lstrcmp(pe.szExeFile, L"Minecraft.Windows.exe") == 0)
			ret = pe.th32ProcessID;
	} while (Process32Next(hProcessSnap, &pe));
	CloseHandle(hProcessSnap);
	return ret;
}

HMODULE FindRemoteModuleAddress(DWORD pid, const wchar_t *path) {
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
		throw std::runtime_error("CreateToolhelp32Snapshot failed");
	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me))
		throw std::runtime_error("Module32First failed");
	DWORD ret = 0;
	do {
		if (!wcscmp(path, me.szExePath))
			return me.hModule;
	} while (Module32Next(hModuleSnap, &me));
	CloseHandle(hModuleSnap);
	return NULL;
}


void CallUsingRemoteThread(HANDLE hProcess, LPVOID lpFunction, LPVOID lpParameter) {
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpFunction, lpParameter, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
}

void CallUsingRemoteThreadWithData(HANDLE hProcess, LPVOID lpFunction, LPCVOID lpData, SIZE_T nDataSize) {
	LPVOID lpRemoteData = VirtualAllocEx(hProcess, NULL, nDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, lpRemoteData, lpData, nDataSize, NULL);
	CallUsingRemoteThread(hProcess, lpFunction, lpRemoteData);
	VirtualFreeEx(hProcess, lpRemoteData, nDataSize, MEM_RELEASE);
}


void GrantAllApplicationPackagesPermission(LPCWSTR lpStr) {
	PACL pAcl, pNewAcl;
	EXPLICIT_ACCESS explicitAccess;
	PSECURITY_DESCRIPTOR ppSecurityDescriptor;

	uint8_t pSid_backing[SECURITY_MAX_SID_SIZE];
	PSID pSid = pSid_backing;
	DWORD cbSid = sizeof(pSid_backing);

	if (!CreateWellKnownSid(WinBuiltinAnyPackageSid, NULL, pSid, &cbSid))
		throw std::runtime_error("CreateWellKnownSid failed");

	if (GetNamedSecurityInfo(lpStr, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pAcl, NULL, &ppSecurityDescriptor) != ERROR_SUCCESS)
		throw std::runtime_error("GetNamedSecurityInfo failed");
	ZeroMemory(&explicitAccess, sizeof(EXPLICIT_ACCESS));
	explicitAccess.grfAccessMode = SET_ACCESS;
	explicitAccess.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	explicitAccess.grfInheritance = 0;;
	explicitAccess.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	explicitAccess.Trustee.pMultipleTrustee = NULL;
	explicitAccess.Trustee.ptstrName = (LPTSTR)pSid;
	explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

	if (SetEntriesInAcl(1, &explicitAccess, pAcl, &pNewAcl) != ERROR_SUCCESS)
		throw std::runtime_error("SetEntriesInAcl failed");
	if (SetNamedSecurityInfo((LPWSTR) lpStr, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewAcl, NULL) != ERROR_SUCCESS) {
		LocalFree(pNewAcl);
		throw std::runtime_error("SetNamedSecurityInfo failed");
	}
	LocalFree(pNewAcl);
}

int main() {
	try {
		auto pid = FindMinecraftPID();
		if (pid == 0) {
			printf("Minecraft is not running.");
			return 1;
		}
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		if (hProcess == NULL)
			throw std::runtime_error("OpenProcess failed");

		std::wstring cwd;
		cwd.resize(MAX_PATH + 1);
		auto cwdLen = GetCurrentDirectory(2 * cwd.size(), &cwd[0]);
		if (cwdLen == 0)
			throw std::runtime_error("GetCurrentDirectory failed");
		cwd.resize(cwdLen);

		// wprintf(L"CWD: %s\n", cwd.data());

		std::wstring libPath = cwd + L"\\Mod.dll";
		std::wstring copyToLibPath = cwd + L"\\Mod_Injected.dll";


		auto hLib = FindRemoteModuleAddress(pid, copyToLibPath.c_str());
		if (hLib != NULL) {
			wprintf(L"Unloading previous version of the mod. (handle = %p)\n", hLib);

			LPVOID lpFreeLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
			CallUsingRemoteThread(hProcess, lpFreeLibrary, hLib);
		}

		if (!CopyFile(libPath.c_str(), copyToLibPath.c_str(), FALSE))
			throw std::runtime_error("CopyFile failed");

		GrantAllApplicationPackagesPermission(copyToLibPath.c_str());

		wprintf(L"Loading mod file: %s\n", copyToLibPath.data());
		LPVOID lpLoadLibraryW = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
		CallUsingRemoteThreadWithData(hProcess, lpLoadLibraryW, copyToLibPath.data(), 2 * copyToLibPath.size() + 2); // size()はnull terminatorを含まないから2を足します

	} catch (std::runtime_error& err) {
		printf("Error: %s\n", err.what());
		return 1;
	}

	return 0;
}
