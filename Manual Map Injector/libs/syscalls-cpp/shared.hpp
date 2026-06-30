#ifndef _SYSCALL_SHARED_HPP_
#define _SYSCALL_SHARED_HPP_

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>

// Ensure PCLIENT_ID is available (winternl.h may define CLIENT_ID but not PCLIENT_ID)
#ifndef PCLIENT_ID
typedef CLIENT_ID* PCLIENT_ID;
#endif

#include "platform.hpp"

namespace syscall::native
{

    [[nodiscard]] constexpr bool isSuccess(NTSTATUS status) noexcept
    {
        return status >= 0;
    }

    
    [[nodiscard]] constexpr HANDLE getCurrentProcess() noexcept
    {
        return reinterpret_cast<HANDLE>(-1);
    }

    enum class ESectionInherit : DWORD 
    {
        VIEW_SHARE = 1,
        VIEW_UNMAP = 2
    };

    enum class ESectionAllocAttributes : ULONG 
    {
        SECTION_COMMIT = SEC_COMMIT,
        SECTION_IMAGE = SEC_IMAGE,
        SECTION_IMAGE_NO_EXECUTE = SEC_IMAGE_NO_EXECUTE,
        SECTION_LARGE_PAGES = SEC_LARGE_PAGES,
        SECTION_NO_CHANGE = 0x00400000, 
        SECTION_RESERVE = SEC_RESERVE,
    };

    struct LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        union {
            LIST_ENTRY HashLinks;
            struct {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        union {
            ULONG TimeDateStamp;
            PVOID LoadedImports;
        };
        _ACTIVATION_CONTEXT* EntryPointActivationContext;
        PVOID PatchInformation;
        LIST_ENTRY ForwarderLinks;
        LIST_ENTRY ServiceTagLinks;
        LIST_ENTRY StaticLinks;
        PVOID ContextInformation;
        ULONG_PTR OriginalBase;
        LARGE_INTEGER LoadTime;
    };

    using NtCreateSection_t = NTSTATUS(NTAPI*)(
        PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle
        );

    using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(
        HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
        ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
        PSIZE_T ViewSize, ESectionInherit InheritDisposition, ULONG AllocationType, ULONG Win32Protect
        );

    using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID BaseAddress);

    using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
        );

    using NtProtectVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtect, PULONG OldProtect
        );

    using NtFreeVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType
        );

    using NtClose_t = NTSTATUS(NTAPI*)(HANDLE Handle);

    using NtWriteVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten
        );

    using NtReadVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead
        );

    using NtOpenProcess_t = NTSTATUS(NTAPI*)(
        PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId
        );

    using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
        PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
        PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
        SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize,
        PVOID AttributeList
        );

    using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
        ULONG SystemInformationClass, PVOID SystemInformation,
        ULONG SystemInformationLength, PULONG ReturnLength
        );

    using RtlCreateHeap_t = PVOID(NTAPI*)(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PVOID Parameters);
    using RtlAllocateHeap_t = PVOID(NTAPI*)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
    using RtlDestroyHeap_t = PVOID(NTAPI*)(PVOID HeapHandle);

    constexpr NTSTATUS STATUS_SUCCESS = 0x00000000L;
    constexpr NTSTATUS STATUS_UNSUCCESSFUL = 0xC0000001L;
    constexpr NTSTATUS STATUS_BUFFER_TOO_SMALL = 0xC0000023L;
    constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xC0000004L;
    constexpr NTSTATUS STATUS_PROCEDURE_NOT_FOUND = 0xC000007A;

    constexpr ULONG SystemProcessInformation = 5;

    struct MY_SYSTEM_PROCESS_INFORMATION {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
    };

} // syscall::native

#endif