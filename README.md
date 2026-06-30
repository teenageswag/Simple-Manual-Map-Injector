# Manual Map Injector

Manual DLL mapper for Windows. Maps a DLL into a target process without using the standard `LoadLibrary` API, making it harder to detect by security software.

## Features

- **x86 / x64** — builds for both architectures
- **SEH exception support** (x64 only, requires `/EHa` or `/EHc`)
- **Direct NTAPI calls** — all sensitive operations (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`, etc.) resolved directly from `ntdll.dll`, bypassing hooked `kernel32`/`kernelbase` exports
- **Process discovery** — finds target by name via `NtQuerySystemInformation`
- **PE header clearing** — erases the DLL header from remote memory after mapping
- **Section cleanup** — removes `.rsrc`, `.reloc`, and optionally `.pdata` sections
- **Section protection** — sets appropriate page protections (RW, RX, RWX) per section flags
- **C++ exception support** (x64) — `_CxxThrowException` stub with `UNWIND_INFO` + `RUNTIME_FUNCTION` for typed catches in manually-mapped DLLs
- **Configurable `DllMain` params** — reason code and reserved parameter

## Architecture

```
src/
  main.cpp          — entry point, argument parsing
  app/app.h|cpp     — orchestrator: init, DLL validation, process lookup, injection
  injector/injector.h|cpp — manual mapping logic (remote memory ops + shellcode)
  process/process.h|cpp   — process discovery (by name) and handle management
libs/
  logger/           — async console + file logger
  syscalls-cpp/     — header-only library for direct syscall stub generation (https://github.com/sapdragon/syscalls-cpp)
```

## Build

Requires MSVC with C++23 support (Visual Studio 2022 / MSVC 14.5+).

```
msbuild Manual-Map-Injector.sln /p:Configuration=Release /p:Platform=x64
```

Output: `build/bin/x64/Release/Manual-Map-Injector.exe`

## Usage

```
Manual-Map-Injector.exe <dll_path> <process_name>
```

**Example:**

```
Manual-Map-Injector.exe "C:\path\to\payload.dll" "target.exe"
```

## Testing

Hello World DLL for testing are included from [carterjones/hello-world-dll](https://github.com/carterjones/hello-world-dll):

- `hello-world.dll`
