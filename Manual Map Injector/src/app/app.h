#pragma once
#include "injector/injector.h"
#include <syscalls-cpp/syscall.hpp>

class App {
public:
	App() = default;
	~App() = default;

	bool Init(wchar_t* dll_path, wchar_t* process_name);
	int Run();

private:
	std::unique_ptr<Injector> m_injector;
};