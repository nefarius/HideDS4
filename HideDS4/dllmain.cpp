/*

The MIT License (MIT)

Copyright (c) 2015 Benjamin "Nefarius" Höglinger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <MinHook.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi")

// MinHook helper function
template <typename T>
inline MH_STATUS MH_CreateHookApiEx(
	LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	return MH_CreateHookApi(
		pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

// type definition of CreateFileW(...) WinAPI
typedef HANDLE(WINAPI* tCreateFileW)(
	_In_     LPCWSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
	);
// pointer to original function
tCreateFileW OriginalCreateFileW = nullptr;

// declaration of hooked function
HANDLE WINAPI DetourCreateFileW(
	_In_     LPCWSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
	);

// type definition of CreateFileA(...) WinAPI
typedef HANDLE(WINAPI* tCreateFileA)(
	_In_     LPCSTR                lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
	);
// pointer to original function
tCreateFileA OriginalCreateFileA = nullptr;

// declaration of hooked function
HANDLE WINAPI DetourCreateFileA(
	_In_     LPCSTR                lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
	);

// just an extra layer of "security" ;)
typedef BOOL (WINAPI* tIsDebuggerPresent)(void);
tIsDebuggerPresent OriginalIsDebuggerPresent = nullptr;
BOOL WINAPI DetourIsDebuggerPresent(void);

int init(void);

// called on DLL load
BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID)
{
	// we don't care about thread attachments/detachments
	DisableThreadLibraryCalls(static_cast<HMODULE>(hInstance));

	if (dwReason != DLL_PROCESS_ATTACH)
		return FALSE;

	// loader lock active; begin work in new thread
	return CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), nullptr, 0, nullptr) > nullptr;
}

// main logic
int init()
{
	// initialize hook engine
	if (MH_Initialize() != MH_OK)
	{
		return -1;
	}

	// create kernel32!CreateFileW hook (unicode)
	if (MH_CreateHookApiEx(L"kernel32", "CreateFileW", &DetourCreateFileW, &OriginalCreateFileW) != MH_OK)
	{
		return -2;
	}

	// create kernel32!CreateFileA hook (ANSI)
	if (MH_CreateHookApiEx(L"kernel32", "CreateFileA", &DetourCreateFileA, &OriginalCreateFileA) != MH_OK)
	{
		return -3;
	}

	// create kernel32!IsDebuggerPresent hook
	if (MH_CreateHookApiEx(L"kernel32", "IsDebuggerPresent", &DetourIsDebuggerPresent, &OriginalIsDebuggerPresent) != MH_OK)
	{
		return -4;
	}

	// enable all hooks
	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
	{
		return -5;
	}

	// block this thread infinitely to keep hooks active
	return WaitForSingleObject(INVALID_HANDLE_VALUE, INFINITE);
}

// fake/hooked CreateFileW function (unicode)
HANDLE WINAPI DetourCreateFileW(
	_In_     LPCWSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
	)
{
	// identify open call for DualShock 4 device
	if (StrStrW(lpFileName, L"\\\\?\\hid#vid_054c&pid_05c4") != nullptr)
	{
		// fake open error
		SetLastError(ERROR_FILE_NOT_FOUND);
		// fake return value
		return INVALID_HANDLE_VALUE;
	}

	// legit call, forward to original function
	return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// fake/hooked CreateFileA function (ANSI)
HANDLE WINAPI DetourCreateFileA(
	_In_     LPCSTR                lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
	)
{
	// identify open call for DualShock 4 device
	if (StrStrA(lpFileName, "\\\\?\\hid#vid_054c&pid_05c4") != nullptr)
	{
		// fake open error
		SetLastError(ERROR_FILE_NOT_FOUND);
		// fake return value
		return INVALID_HANDLE_VALUE;
	}

	// legit call, forward to original function
	return OriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// there is no debugger!
BOOL WINAPI DetourIsDebuggerPresent(void)
{
	// ofc. not! =)
	return FALSE;
}
