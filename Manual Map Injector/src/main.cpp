#include "app/app.h"
#include <logger/logger.h>
#include <iostream>

int wmain(int argc, wchar_t* argv[]) {
	log::ConsoleConfig cfg;
	cfg.title = "[ Manual Map Injector ]";
	log::init_console(cfg);

	if (argc < 3) {
		char exe_name[MAX_PATH];
		size_t converted_chars = 0;
		wcstombs_s(&converted_chars, exe_name, sizeof(exe_name), argv[0], _TRUNCATE);

		log::error("Initialization failed: Missing required arguments.");
		log::info("Usage: manual-map-injector.exe <dll_path> <process_name>");
		log::info("Example: manual-map-injector.exe 'C:\\cheats\\hack.dll' 'cs2.exe'");
		std::cin.get();

		return 1;
	}

	int exit_code = 0;
	{
		App app;
		// passing the dll_path and target_process_name
		if (app.Init(argv[1], argv[2])) {
			exit_code = app.Run();
		}
		else {
			exit_code = 1;
		}
	}
}
