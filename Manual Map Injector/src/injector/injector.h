#pragma once

#include <Windows.h>
#include <string>
#include <syscalls-cpp/syscall.hpp>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;

#ifdef _WIN64
	void* pCxxThrowStub;
#endif
};

class Injector {
public:
	Injector() = default;
	~Injector() = default;

	bool Inject(SyscallSectionDirect& sysmgr,
		HANDLE hProcess,
		BYTE* pSrcData,
		SIZE_T FileSize,
		bool ClearHeader = true,
		bool ClearNonNeededSections = true,
		bool AdjustProtections = true,
		bool SEHExceptionSupport = true,
		DWORD fdwReason = DLL_PROCESS_ATTACH,
		LPVOID lpReserved = nullptr);

private:
	static void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);

	BYTE* RemoteAlloc(SyscallSectionDirect& sysmgr, HANDLE hProc, SIZE_T size, ULONG protect);
	bool RemoteWrite(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID base, const void* data, SIZE_T size);
	bool RemoteRead(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID base, void* out, SIZE_T size);
	bool RemoteProtect(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID base, SIZE_T size, ULONG newProtect, ULONG* oldProtect);
	bool RemoteFree(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID base, SIZE_T size = 0);
	HANDLE RemoteCreateThread(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID startAddr, PVOID param);
};
