#include "app.h"
#include <memory>

bool App::Init(wchar_t* dll_path, wchar_t* process_name) {
	// инициализировать syscalls, если надо
	// проверить что длл и процесс корректные
	m_injector = std::make_unique<Injector>();
	return true;
}

int App::Run() {
	// запустить инжектор и выполнить инъекцию
	return 0;
}
