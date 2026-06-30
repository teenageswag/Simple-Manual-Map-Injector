#pragma once

#include <memory>
#include <string>
#include <vector>
#include <syscalls-cpp/syscall.hpp>
#include "injector/injector.h"
#include "process/process.h"

class App {
public:
	App() = default;
	~App() = default;

	bool Init(const wchar_t* dllPath, const wchar_t* processName);
	int Run();

private:
	bool LoadDll(const wchar_t* dllPath);
	bool validateDll(const std::vector<BYTE>& data);

	SyscallSectionDirect m_syscalls;
	std::unique_ptr<Process> m_process;
	std::unique_ptr<Injector> m_injector;

	std::vector<BYTE> m_dllData;
	std::wstring m_dllPath;
	std::wstring m_processName;
};
