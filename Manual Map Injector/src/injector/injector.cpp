#include "injector.h"
#include <logger/logger.h>
#include <vector>
#include <cstring>
#include <string_view>

#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

#ifdef _WIN64
#define RELOC_FLAG(reloc) (((reloc) >> 12) == IMAGE_REL_BASED_DIR64)
#else
#define RELOC_FLAG(reloc) (((reloc) >> 12) == IMAGE_REL_BASED_HIGHLOW)
#endif

// -------------------
// syscalls helpers
// -------------------
static HMODULE GetNtdll() {
	static HMODULE h = GetModuleHandleW(L"ntdll.dll");
	return h;
}

template<typename T>
static T ResolveNtdll(const char* name) {
	return reinterpret_cast<T>(syscall::native::getExportAddress(GetNtdll(), name));
}

BYTE* Injector::RemoteAlloc(SyscallSectionDirect& sysmgr, HANDLE hProc, SIZE_T size, ULONG protect) {
	auto fNtAlloc = ResolveNtdll<syscall::native::NtAllocateVirtualMemory_t>("NtAllocateVirtualMemory");
	if (!fNtAlloc) {
		log::error("Can't resolve NtAllocateVirtualMemory");
		return nullptr;
	}

	PVOID baseAddr = nullptr;
	SIZE_T regionSize = size;
	NTSTATUS status = fNtAlloc(hProc, &baseAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, protect);

	if (!NT_SUCCESS(status) || !baseAddr) {
		log::error("NtAllocateVirtualMemory failed: 0x{:08X}", static_cast<unsigned long>(status));
		return nullptr;
	}
	return reinterpret_cast<BYTE*>(baseAddr);
}

bool Injector::RemoteWrite(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID base, const void* data, SIZE_T size) {
	auto fNtWrite = ResolveNtdll<syscall::native::NtWriteVirtualMemory_t>("NtWriteVirtualMemory");
	if (!fNtWrite) {
		log::error("Can't resolve NtWriteVirtualMemory");
		return false;
	}

	SIZE_T bytesWritten = 0;
	NTSTATUS status = fNtWrite(hProc, base, const_cast<PVOID>(data), size, &bytesWritten);

	if (!NT_SUCCESS(status)) {
		log::error("NtWriteVirtualMemory failed: 0x{:08X}", static_cast<unsigned long>(status));
		return false;
	}
	return bytesWritten == size;
}

bool Injector::RemoteRead(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID base, void* out, SIZE_T size) {
	auto fNtRead = ResolveNtdll<syscall::native::NtReadVirtualMemory_t>("NtReadVirtualMemory");
	if (!fNtRead) {
		log::error("Can't resolve NtReadVirtualMemory");
		return false;
	}

	SIZE_T bytesRead = 0;
	NTSTATUS status = fNtRead(hProc, base, out, size, &bytesRead);

	if (!NT_SUCCESS(status)) {
		log::error("NtReadVirtualMemory failed: 0x{:08X}", static_cast<unsigned long>(status));
		return false;
	}
	return bytesRead == size;
}

bool Injector::RemoteProtect(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID base, SIZE_T size, ULONG newProtect, ULONG* oldProtect) {
	auto fNtProtect = ResolveNtdll<syscall::native::NtProtectVirtualMemory_t>("NtProtectVirtualMemory");
	if (!fNtProtect) {
		log::error("Can't resolve NtProtectVirtualMemory");
		return false;
	}

	PVOID baseAddr = base;
	SIZE_T regionSize = size;
	ULONG oldProt = 0;
	NTSTATUS status = fNtProtect(hProc, &baseAddr, &regionSize, newProtect, &oldProt);

	if (oldProtect) {
		*oldProtect = oldProt;
	}
	return NT_SUCCESS(status);
}

bool Injector::RemoteFree(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID base, SIZE_T size) {
	auto fNtFree = ResolveNtdll<syscall::native::NtFreeVirtualMemory_t>("NtFreeVirtualMemory");
	if (!fNtFree) {
		log::error("Can't resolve NtFreeVirtualMemory");
		return false;
	}

	PVOID baseAddr = base;
	SIZE_T regionSize = size;
	NTSTATUS status = fNtFree(hProc, &baseAddr, &regionSize, MEM_RELEASE);
	return NT_SUCCESS(status);
}

HANDLE Injector::RemoteCreateThread(SyscallSectionDirect& sysmgr, HANDLE hProc, PVOID startAddr, PVOID param) {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		return nullptr;
	}

	auto fNtCreateThreadEx = reinterpret_cast<syscall::native::NtCreateThreadEx_t>(syscall::native::getExportAddress(hNtdll, "NtCreateThreadEx"));
	if (!fNtCreateThreadEx) {
		log::error("Can't resolve NtCreateThreadEx");
		return nullptr;
	}

	HANDLE hThread = nullptr;
	NTSTATUS status = fNtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		hProc,
		startAddr,
		param,
		0,      // CreateFlags
		0,      // ZeroBits
		0,      // StackSize
		0,      // MaxStackSize
		nullptr // AttributeList
	);

	if (!NT_SUCCESS(status) || !hThread) {
		log::error("NtCreateThreadEx failed: 0x{:08X}", static_cast<unsigned long>(status));
		return nullptr;
	}
	return hThread;
}

// -------------------
// injection logic
// -------------------
bool Injector::Inject(SyscallSectionDirect& sysmgr,
	HANDLE hProcess,
	BYTE* pSrcData,
	SIZE_T FileSize,
	bool ClearHeader,
	bool ClearNonNeededSections,
	bool AdjustProtections,
	bool SEHExceptionSupport,
	DWORD fdwReason,
	LPVOID lpReserved)
{
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	BYTE* pTargetBase = nullptr;

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
		log::error("Invalid file format: bad MZ header");
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

	if (pOldFileHeader->Machine != CURRENT_ARCH) {
		log::error(
			"Architecture mismatch: DLL is {} but injector is {}",
			pOldFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "x86",
			CURRENT_ARCH == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "x86"
		);
		return false;
	}

	// Allocate memory in target process
	pTargetBase = RemoteAlloc(sysmgr, hProcess, pOldOptHeader->SizeOfImage, PAGE_READWRITE);
	if (!pTargetBase) {
		log::error("Target process memory allocation failed");
		return false;
	}

	// Set full RWX for initial writing
	ULONG oldProt = 0;
	RemoteProtect(sysmgr, hProcess, pTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProt);

	// Prepare mapping data
	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.pRtlAddFunctionTable = reinterpret_cast<f_RtlAddFunctionTable>(
		syscall::native::getExportAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddFunctionTable"));
#endif
	data.pbase = pTargetBase;
	data.fdwReasonParam = fdwReason;
	data.reservedParam = lpReserved;
	data.SEHSupport = SEHExceptionSupport;

#ifdef _WIN64
	// Build _CxxThrowException replacement stub
	data.pCxxThrowStub = nullptr;
	if (SEHExceptionSupport) {
		auto hK32 = GetModuleHandleW(L"kernel32.dll");
		FARPROC pRaiseEx = hK32
			? reinterpret_cast<FARPROC>(syscall::native::getExportAddress(hK32, "RaiseException"))
			: nullptr;

		void* stubMem = pRaiseEx
			? RemoteAlloc(sysmgr, hProcess, 0x1000, PAGE_EXECUTE_READWRITE)
			: nullptr;

		if (!stubMem) {
			log::warn("Couldn't allocate CxxThrow stub; typed catches may fail");
		}
		else {
			BYTE blob[0xB0] = {};
			BYTE stub[] = {
				0x48, 0x83, 0xEC, 0x48,                         // sub rsp, 0x48
				0xC7, 0x44, 0x24, 0x20, 0x20, 0x05, 0x93, 0x19, // mov [rsp+0x20], 19930520h (EH_MAGIC_NUMBER1)
				0xC7, 0x44, 0x24, 0x24, 0x00, 0x00, 0x00, 0x00, // mov [rsp+0x24], 0
				0x48, 0x89, 0x4C, 0x24, 0x28,                   // mov [rsp+0x28], rcx ; obj
				0x48, 0x89, 0x54, 0x24, 0x30,                   // mov [rsp+0x30], rdx ; ThrowInfo
				0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // movabs rax, IMAGE_BASE (patched at offset 32)
				0x48, 0x89, 0x44, 0x24, 0x38,                   // mov [rsp+0x38], rax ; param[3]
				0xB9, 0x63, 0x73, 0x6D, 0xE0,                   // mov ecx, 0xE06D7363
				0xBA, 0x01, 0,0,0,                              // mov edx, 1 (NONCONTINUABLE)
				0x41, 0xB8, 0x04, 0,0,0,                        // mov r8d, 4
				0x4C, 0x8D, 0x4C, 0x24, 0x20,                   // lea r9, [rsp+0x20]
				0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // movabs rax, RaiseException (patched at offset 68)
				0xFF, 0xD0,                                     // call rax
				0xCC,                                           // int3 (never reached)
			};
			ULONG_PTR imageBase = reinterpret_cast<ULONG_PTR>(pTargetBase);
			ULONG_PTR raiseExceptionAddr = reinterpret_cast<ULONG_PTR>(pRaiseEx);
			memcpy(stub + 32, &imageBase, 8);
			memcpy(stub + 68, &raiseExceptionAddr, 8);
			memcpy(blob, stub, sizeof(stub));

			blob[0x80] = 0x01; // Version 1, flags 0
			blob[0x81] = 0x04; // SizeOfProlog (sub rsp, 0x48 is 4 bytes)
			blob[0x82] = 0x01; // CountOfCodes
			blob[0x83] = 0x00; // FrameRegister/FrameOffset
			blob[0x84] = 0x04; // CodeOffset
			blob[0x85] = 0x82; // (OpInfo=8 << 4) | UWOP_ALLOC_SMALL(2)

			DWORD beginAddr = 0;
			DWORD endAddr = static_cast<DWORD>(sizeof(stub));
			DWORD unwindRva = 0x80;
			memcpy(blob + 0xA0, &beginAddr, 4);
			memcpy(blob + 0xA4, &endAddr, 4);
			memcpy(blob + 0xA8, &unwindRva, 4);

			if (RemoteWrite(sysmgr, hProcess, stubMem, blob, sizeof(blob))) {
				data.pCxxThrowStub = stubMem;
			}
			else {
				log::warn("Couldn't write CxxThrow stub; typed catches may fail");
			}
		}
	}
#endif

	// Write PE header
	if (!RemoteWrite(sysmgr, hProcess, pTargetBase, pSrcData, 0x1000)) { // Only first 0x1000 bytes for the header
		log::error("Can't write file header");
		RemoteFree(sysmgr, hProcess, pTargetBase);
		return false;
	}

	// Write sections
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!RemoteWrite(sysmgr, hProcess,
				pTargetBase + pSectionHeader->VirtualAddress,
				pSrcData + pSectionHeader->PointerToRawData,
				pSectionHeader->SizeOfRawData)) {
				log::error("Can't map section '{}'", reinterpret_cast<char*>(pSectionHeader->Name));
				RemoteFree(sysmgr, hProcess, pTargetBase);
				return false;
			}
		}
	}

	// Allocate and write mapping data
	BYTE* MappingDataAlloc = RemoteAlloc(sysmgr, hProcess, sizeof(MANUAL_MAPPING_DATA), PAGE_READWRITE);
	if (!MappingDataAlloc) {
		log::error("Mapping data allocation failed");
		RemoteFree(sysmgr, hProcess, pTargetBase);
		return false;
	}

	if (!RemoteWrite(sysmgr, hProcess, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA))) {
		log::error("Can't write mapping data");
		RemoteFree(sysmgr, hProcess, pTargetBase);
		RemoteFree(sysmgr, hProcess, MappingDataAlloc);
		return false;
	}

	// Allocate and write shellcode
	void* pShellcode = RemoteAlloc(sysmgr, hProcess, 0x1000, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		log::error("Shellcode allocation failed");
		RemoteFree(sysmgr, hProcess, pTargetBase);
		RemoteFree(sysmgr, hProcess, MappingDataAlloc);
		return false;
	}

	if (!RemoteWrite(sysmgr, hProcess, pShellcode, Shellcode, 0x1000)) {
		log::error("Can't write shellcode");
		RemoteFree(sysmgr, hProcess, pTargetBase);
		RemoteFree(sysmgr, hProcess, MappingDataAlloc);
		RemoteFree(sysmgr, hProcess, pShellcode);
		return false;
	}

	log::info("Mapped DLL at {:p}", reinterpret_cast<void*>(pTargetBase));
	log::info("Mapping info at {:p}", reinterpret_cast<void*>(MappingDataAlloc));
	log::info("Shellcode at {:p}", pShellcode);

	// Create remote thread
	HANDLE hThread = RemoteCreateThread(sysmgr, hProcess, pShellcode, MappingDataAlloc);
	if (!hThread) {
		log::error("Thread creation failed");
		RemoteFree(sysmgr, hProcess, pTargetBase);
		RemoteFree(sysmgr, hProcess, MappingDataAlloc);
		RemoteFree(sysmgr, hProcess, pShellcode);
		return false;
	}

	// Close thread handle via syscall
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	auto fNtClose = reinterpret_cast<syscall::native::NtClose_t>(syscall::native::getExportAddress(hNtdll, "NtClose"));
	if (fNtClose) fNtClose(hThread);

	log::info("Thread created, waiting for completion...");

	// Wait for shellcode to finish
	HINSTANCE hCheck = nullptr;
	DWORD tStart = static_cast<DWORD>(GetTickCount64());
	const DWORD kInjectTimeoutMs = 30000;

	while (!hCheck) {
		DWORD exitcode = 0;
		// NtQueryInformationProcess to check if alive (using GetExitCodeProcess fallback is OK here
		// since it's just a simple check, not a security-sensitive operation)
		GetExitCodeProcess(hProcess, &exitcode);
		if (exitcode != STILL_ACTIVE) {
			log::error("Process crashed, exit code: 0x{:08X}", exitcode);
			return false;
		}

		if (GetTickCount64() - tStart > kInjectTimeoutMs) {
			log::error("Injection timed out after {} ms", kInjectTimeoutMs);
			return false;
		}

		MANUAL_MAPPING_DATA data_checked{ 0 };
		if (!RemoteRead(sysmgr, hProcess, MappingDataAlloc, &data_checked, sizeof(data_checked))) {
			Sleep(10);
			continue;
		}
		hCheck = data_checked.hMod;

		if (hCheck == reinterpret_cast<HINSTANCE>(0x404040)) {
			log::error("Wrong mapping pointer");
			RemoteFree(sysmgr, hProcess, pTargetBase);
			RemoteFree(sysmgr, hProcess, MappingDataAlloc);
			RemoteFree(sysmgr, hProcess, pShellcode);
			return false;
		}
		else if (hCheck == reinterpret_cast<HINSTANCE>(0x505050)) {
			log::warn("Exception support failed");
		}

		Sleep(10);
	}

	// Post-injection cleanup
	std::vector<BYTE> emptyBuffer(0x1000, 0);

	// Clear PE header
	if (ClearHeader) {
		if (!RemoteWrite(sysmgr, hProcess, pTargetBase, emptyBuffer.data(), 0x1000)) {
			log::warn("Can't clear PE header");
		}
	}

	// Clear non-needed sections
	if (ClearNonNeededSections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				char* secName = reinterpret_cast<char*>(pSectionHeader->Name);
				if ((SEHExceptionSupport ? 0 : strcmp(secName, ".pdata") == 0) ||
					strcmp(secName, ".rsrc") == 0 ||
					strcmp(secName, ".reloc") == 0) {
					log::info("Clearing section '{}'", secName);
					SIZE_T clearSize = pSectionHeader->Misc.VirtualSize;
					std::vector<BYTE> sectionZero(clearSize, 0);
					if (!RemoteWrite(sysmgr, hProcess,
						pTargetBase + pSectionHeader->VirtualAddress,
						sectionZero.data(), clearSize)) {
						log::error("Can't clear section '{}'", secName);
					}
				}
			}
		}
	}

	// Adjust section protections
	if (AdjustProtections) {
		pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
			if (pSectionHeader->Misc.VirtualSize) {
				DWORD newProt = PAGE_READONLY;

				if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
					newProt = PAGE_READWRITE;
				}
				else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
					newProt = PAGE_EXECUTE_READ;
				}

				ULONG oldP = 0;
				if (RemoteProtect(sysmgr, hProcess,
					pTargetBase + pSectionHeader->VirtualAddress,
					pSectionHeader->Misc.VirtualSize, newProt, &oldP)) {

					size_t nameLen = strnlen(reinterpret_cast<const char*>(pSectionHeader->Name), 8);
					std::string_view sectionName(reinterpret_cast<const char*>(pSectionHeader->Name), nameLen);
					log::info("Section '{}' set to 0x{:X}", sectionName, newProt);
				}
				else {
					log::error("Failed to set protection on section '{}'", pSectionHeader->Name);
				}
			}
		}

		// Make header read-only
		ULONG oldP = 0;
		RemoteProtect(sysmgr, hProcess, pTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &oldP);
	}

	// Clear and free shellcode + mapping data
	RemoteWrite(sysmgr, hProcess, pShellcode, emptyBuffer.data(), 0x1000);
	RemoteFree(sysmgr, hProcess, pShellcode);
	RemoteFree(sysmgr, hProcess, MappingDataAlloc);

	return true;
}

// -------------------
// shellcode logic
// -------------------
#pragma runtime_checks( "", off )
#pragma optimize( "", off )

void __stdcall Injector::Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) {
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				reinterpret_cast<uintptr_t>(pRelocData) +
				pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(
							pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
					reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	// Resolve imports
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk) {
				pThunkRef = pFuncRef;
			}

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
#ifdef _WIN64
					// Detect "_CxxThrowException" by name (char-by-char to avoid
					// referencing string literals from the injector's .rdata).
					const char* n = pImport->Name;
					bool isCxxThrow =
						pData->pCxxThrowStub &&
						n[0] == '_' && n[1] == 'C' && n[2] == 'x' && n[3] == 'x' &&
						n[4] == 'T' && n[5] == 'h' && n[6] == 'r' && n[7] == 'o' &&
						n[8] == 'w' && n[9] == 'E' && n[10] == 'x' && n[11] == 'c' &&
						n[12] == 'e' && n[13] == 'p' && n[14] == 't' && n[15] == 'i' &&
						n[16] == 'o' && n[17] == 'n' && n[18] == '\0';

					if (isCxxThrow) {
						*pFuncRef = reinterpret_cast<ULONG_PTR>(pData->pCxxThrowStub);
					}
					else
#endif
					{
						*pFuncRef = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, pImport->Name));
					}
				}
			}
			++pImportDescr;
		}
	}

	// Process TLS
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback) {
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	bool ExceptionSupportFailed = false;

#ifdef _WIN64
	if (pData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
				reinterpret_cast<DWORD64>(pBase))) {
				ExceptionSupportFailed = true;
			}
		}
		// Register the CxxThrow stub's own RUNTIME_FUNCTION so the OS unwinder
		// can walk through it on its way back to the throw site's frame.
		if (pData->pCxxThrowStub) {
			BYTE* stubBase = static_cast<BYTE*>(pData->pCxxThrowStub);
			_RtlAddFunctionTable(reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(stubBase + 0xA0), 1, reinterpret_cast<DWORD64>(stubBase));
		}
	}
#endif

	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);

	if (ExceptionSupportFailed)
		pData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
