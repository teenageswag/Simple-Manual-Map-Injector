#pragma once

#include <Windows.h>
#include <string>
#include <syscalls-cpp/syscall.hpp>

class Process {
public:
	Process() = default;
	~Process();

	Process(const Process&) = delete;
	Process& operator=(const Process&) = delete;
	Process(Process&& other) noexcept;
	Process& operator=(Process&& other) noexcept;

	bool OpenByName(SyscallSectionDirect& sysmgr, const wchar_t* processName);
	bool OpenByPid(SyscallSectionDirect& sysmgr, DWORD pid);

	HANDLE GetHandle() const { return m_handle; }
	DWORD GetPid() const { return m_pid; }
	bool IsOpen() const { return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE; }

	void Close();

private:
	HANDLE m_handle = nullptr;
	DWORD m_pid = 0;

	bool OpenHandle(SyscallSectionDirect& sysmgr, DWORD targetPid);
	static DWORD FindPidByName(SyscallSectionDirect& sysmgr, const wchar_t* name);
};
