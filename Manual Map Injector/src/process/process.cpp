#include "process.h"
#include <logger/logger.h>
#include <algorithm>

Process::~Process() {
	Close();
}

Process::Process(Process&& other) noexcept
	: m_handle(other.m_handle), m_pid(other.m_pid) {
	other.m_handle = nullptr;
	other.m_pid = 0;
}

Process& Process::operator=(Process&& other) noexcept {
	if (this != &other) {
		Close();
		m_handle = other.m_handle;
		m_pid = other.m_pid;
		other.m_handle = nullptr;
		other.m_pid = 0;
	}
	return *this;
}

void Process::Close() {
	if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
		// Use getExportAddress with the wchar_t overload to find ntdll
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		if (hNtdll) {
			auto fNtClose = reinterpret_cast<syscall::native::NtClose_t>(
				syscall::native::getExportAddress(hNtdll, "NtClose"));
			if (fNtClose) {
				fNtClose(m_handle);
			}
		}
		m_handle = nullptr;
		m_pid = 0;
	}
}

bool Process::OpenByName(SyscallSectionDirect& sysmgr, const wchar_t* processName) {
	DWORD pid = FindPidByName(sysmgr, processName);
	if (pid == 0) {
		log::error("Process not found by name");
		return false;
	}
	log::info("Found process with PID {}", pid);
	return OpenHandle(sysmgr, pid);
}

bool Process::OpenByPid(SyscallSectionDirect& sysmgr, DWORD pid) {
	return OpenHandle(sysmgr, pid);
}

bool Process::OpenHandle(SyscallSectionDirect& sysmgr, DWORD targetPid) {
	if (m_handle) {
		Close();
	}

	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		log::error("Can't get ntdll base");
		return false;
	}

	auto fNtOpenProcess = reinterpret_cast<syscall::native::NtOpenProcess_t>(syscall::native::getExportAddress(hNtdll, "NtOpenProcess"));
	if (!fNtOpenProcess) {
		log::error("Can't resolve NtOpenProcess");
		return false;
	}

	CLIENT_ID clientId{};
	clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(targetPid));
	clientId.UniqueThread = nullptr;

	OBJECT_ATTRIBUTES objAttr{};
	InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);

	HANDLE hProcess = nullptr;
	NTSTATUS status = fNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId);

	if (!NT_SUCCESS(status) || !hProcess) {
		log::error("NtOpenProcess failed: 0x{:08X}", static_cast<unsigned long>(status));
		return false;
	}

	m_handle = hProcess;
	m_pid = targetPid;
	return true;
}

DWORD Process::FindPidByName(SyscallSectionDirect& sysmgr, const wchar_t* name) {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		log::error("Can't get ntdll base");
		return 0;
	}

	auto fNtQuerySI = reinterpret_cast<syscall::native::NtQuerySystemInformation_t>(syscall::native::getExportAddress(hNtdll, "NtQuerySystemInformation"));
	if (!fNtQuerySI) {
		log::error("Can't resolve NtQuerySystemInformation");
		return 0;
	}

	ULONG bufferSize = 0;
	NTSTATUS status = fNtQuerySI(syscall::native::SystemProcessInformation, nullptr, 0, &bufferSize);

	if (status != syscall::native::STATUS_INFO_LENGTH_MISMATCH &&
		status != syscall::native::STATUS_BUFFER_TOO_SMALL) {
		log::error("NtQuerySystemInformation sizing failed: 0x{:08X}", static_cast<unsigned long>(status));
		return 0;
	}

	bufferSize *= 2;
	std::vector<BYTE> buffer(bufferSize);

	status = fNtQuerySI(syscall::native::SystemProcessInformation, buffer.data(), bufferSize, &bufferSize);

	if (!NT_SUCCESS(status)) {
		log::error("NtQuerySystemInformation data failed: 0x{:08X}", static_cast<unsigned long>(status));
		return 0;
	}

	auto* pInfo = reinterpret_cast<syscall::native::MY_SYSTEM_PROCESS_INFORMATION*>(buffer.data());
	DWORD resultPid = 0;

	while (true) {
		if (pInfo->ImageName.Buffer && pInfo->ImageName.Length > 0) {
			std::wstring wname(pInfo->ImageName.Buffer, pInfo->ImageName.Length / sizeof(wchar_t));

			if (wname.size() == std::wcslen(name)) {
				bool match = true;
				for (size_t i = 0; i < wname.size(); ++i) {
					if (towlower(wname[i]) != towlower(name[i])) {
						match = false;
						break;
					}
				}
				if (match) {
					resultPid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pInfo->UniqueProcessId));
					break;
				}
			}
		}

		if (pInfo->NextEntryOffset == 0) {
			break;
		}
		pInfo = reinterpret_cast<syscall::native::MY_SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<BYTE*>(pInfo) + pInfo->NextEntryOffset);
	}

	return resultPid;
}
