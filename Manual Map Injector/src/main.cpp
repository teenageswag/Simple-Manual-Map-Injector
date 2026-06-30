#include "app/app.h"
#include <logger/logger.h>
#include <iostream>

int wmain(int argc, wchar_t* argv[]) {
	log::ConsoleConfig cfg;
	cfg.title = "[ Manual Map Injector ]";
	log::init_console(cfg);

	if (argc < 3) {
		log::error("Missing required arguments");
		log::info("Usage: manual-map-injector.exe <dll_path> <process_name>");
		log::info("Example: manual-map-injector.exe 'C:\\cheats\\hack.dll' 'cs2.exe'");
		return 1;
	}

	int exit_code = 0;
	{
		App app;
		if (app.Init(argv[1], argv[2])) {
			exit_code = app.Run();
		}
		else {
			exit_code = 1;
		}
	}

	return exit_code;
}
