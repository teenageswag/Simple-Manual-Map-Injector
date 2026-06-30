#include "app.h"
#include <logger/logger.h>
#include <fstream>
#include <memory>

bool App::Init(const wchar_t* dllPath, const wchar_t* processName) {
	m_dllPath = dllPath;
	m_processName = processName;

	if (!m_syscalls.initialize({ SYSCALL_ID("ntdll.dll") })) {
		log::error("Failed to initialize syscalls");
		return false;
	}

	if (!LoadDll(dllPath)) {
		return false;
	}
	m_process = std::make_unique<Process>();
	if (!m_process->OpenByName(m_syscalls, processName)) {
		log::error("Failed to open target process");
		return false;
	}
	log::info("Target process opened: PID {}", m_process->GetPid());

	m_injector = std::make_unique<Injector>();
	return true;
}

int App::Run() {
	bool success = m_injector->Inject(
		m_syscalls,
		m_process->GetHandle(),
		m_dllData.data(),
		m_dllData.size()
	);

	if (success) {
		log::info("Injection completed successfully");
	}
	else {
		log::error("Injection failed");
	}

	return success;
}

bool App::LoadDll(const wchar_t* dllPath) {
	std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		log::error("Can't open DLL file");
		return false;
	}

	auto fileSize = file.tellg();
	if (fileSize <= 0) {
		log::error("DLL file is empty");
		return false;
	}
	file.seekg(0);

	m_dllData.resize(static_cast<size_t>(fileSize));
	file.read(reinterpret_cast<char*>(m_dllData.data()), fileSize);
	if (!validateDll(m_dllData)) {
		log::error("DLL validation failed");
		return false;
	}
	return true;
}

bool App::validateDll(const std::vector<BYTE>& data) {
	// MZ header
	if (m_dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
		log::error("DLL too small for DOS header");
		return false;
	}

	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_dllData.data());
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		log::error("Invalid DLL: bad MZ signature");
		return false;
	}

	// NT headers
	if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > m_dllData.size()) {
		log::error("Invalid DLL: NT header offset out of bounds");
		return false;
	}

	auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(m_dllData.data() + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		log::error("Invalid DLL: bad NT signature");
		return false;
	}

	// Architecture
#ifdef _WIN64
	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		log::error("DLL architecture mismatch: expected x64, got x86");
		return false;
	}
#else
	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
		log::error("DLL architecture mismatch: expected x86, got x64");
		return false;
	}
#endif

	log::info("DLL loaded: {} bytes ({})", m_dllData.size(), nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : "x86");
	return true;
}
