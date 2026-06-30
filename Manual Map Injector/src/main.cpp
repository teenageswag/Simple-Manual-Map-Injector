#include "app/app.h"

int wmain(int argc, wchar_t* dll_path[], wchar_t* process_name[]) {

	int exit_code = 0;
	{
		App app;
		if (app.Init()) {
			exit_code = app.Run();
		}
		else {
			exit_code = 1;
		}
	}
}
