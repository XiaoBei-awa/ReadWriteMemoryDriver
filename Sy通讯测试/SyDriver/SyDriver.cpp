#include "SyDriver.h"
#include <chrono>

DWORD ERRORCODE;

bool SyDriver::CallTest()
{
	INFO_STRUCT info{};
	info.Type = CODE_CALLTEST;

	DWORD Results = NtOpenFile((PHANDLE)&info, 0, 0, 0, 0x20061128, 0x123456);

	if (Results == 状态_成功) return true;
	ERRORCODE = Results;
	return false;
}

bool SyDriver::SetTargetProcess(HANDLE PID)
{
	typedef struct _SETPROCESS
	{
		HANDLE PID;
	} SETPROCESS, *PSETPROCESS;
	SETPROCESS pBuffer{ PID };

	INFO_STRUCT info{ CODE_SETPROCESS , &pBuffer , sizeof(SETPROCESS) };

	DWORD Results = NtOpenFile((PHANDLE)&info, NULL, NULL, NULL, 0x20061128, 0x123456);

	if (Results == 状态_成功) return true;
	ERRORCODE = Results;
	return false;
}

DWORD64 SyDriver::GetModuleBase(const wchar_t* ModuleName)
{
	DWORD64 Buffer = 0;
	UNICODE_STRING wname{};
	RtlInitUnicodeString(&wname, (PCWSTR)ModuleName);

	typedef struct _GET_MODULE_BASE_BUFFER {
		PVOID ModuleNameBuffer;
		PVOID OutBuffer;
	} GET_MODULE_BASE_BUFFER, *PGET_MODULE_BASE_BUFFER;
	GET_MODULE_BASE_BUFFER pBuffer{ wname.Buffer, &Buffer };

	INFO_STRUCT info{ CODE_GETMODULEBASE , &pBuffer , sizeof(GET_MODULE_BASE_BUFFER) };

	DWORD Results = NtOpenFile((PHANDLE)&info, NULL, NULL, NULL, 0x20061128, 0x123456);

	if (Results == 状态_成功) return Buffer;
	ERRORCODE = Results;
	return 0;
}

bool SyDriver::ReadMemory(DWORD64 Address, PVOID Buffer, size_t Size)
{
	typedef struct _READ_MEMORY
	{
		ULONG64 Address;
		PVOID Buffer;
		SIZE_T Size;
	} READ_MEMORY, *PREAD_MEMORY;
	READ_MEMORY pBuffer{ Address, Buffer, Size };

	INFO_STRUCT info{ CODE_READMEMORY , &pBuffer , sizeof(READ_MEMORY) };

	DWORD Results = NtOpenFile((PHANDLE)&info, NULL, NULL, NULL, 0x20061128, 0x123456);

	if (Results == 状态_成功) return true;
	ERRORCODE = Results;
	return false;
}

bool SyDriver::WriteMemory(DWORD64 Address, PVOID Buffer, size_t Size)
{
    typedef struct _WRITE_MEMORY
	{
		ULONG64 Address;
		PVOID Buffer;
		SIZE_T Size;
	} WRITE_MEMORY, *PWRITE_MEMORY;
	WRITE_MEMORY pBuffer{ Address, Buffer, Size };

	INFO_STRUCT info{ CODE_WRITEMEMORY , &pBuffer , sizeof(WRITE_MEMORY) };

	DWORD Results = NtOpenFile((PHANDLE)&info, NULL, NULL, NULL, 0x20061128, 0x123456);

	if (Results == 状态_成功) return true;
	ERRORCODE = Results;
	return false;
}

bool SyDriver::AllocMemory(DWORD64 Address, PVOID Buffer, size_t Size)
{
	typedef struct _ALLOC_MEMORY {
		ULONG64 Address;
		PVOID Buffer;
		SIZE_T Size;
	} ALLOC_MEMORY, *PALLOC_MEMORY;
	ALLOC_MEMORY pBuffer{ Address, Buffer, Size };

	INFO_STRUCT info{ CODE_ALLOCMEMORY, &pBuffer, sizeof(ALLOC_MEMORY) };

	DWORD Results = NtOpenFile((PHANDLE)&info, NULL, NULL, NULL, 0x20061128, 0x123456);

	if (Results == 状态_成功) return true;
	ERRORCODE = Results;
	return false;
}

bool SyDriver::FreeMemory(DWORD64 Address, size_t Size)
{
	typedef struct _FREE_MEMORY {
		ULONG64 Address;
		SIZE_T Size;
	} FREE_MEMORY, *PFREE_MEMORY;
	FREE_MEMORY pBuffer{ Address, Size, };

	INFO_STRUCT info{ CODE_FREEMEMORY, &pBuffer, sizeof(FREE_MEMORY) };

	DWORD Results = NtOpenFile((PHANDLE)&info, NULL, NULL, NULL, 0x20061128, 0x123456);

	if (Results == 状态_成功) return true;
	ERRORCODE = Results;
	return false;
}

bool SyDriver::LockMemoryR3(HANDLE PID, DWORD64 Address, size_t Size)
{
	typedef struct _LOCK_MEMORY
	{
		HANDLE PID;
		ULONG64 Address;
		SIZE_T Size;
	}LOCK_MEMORY, *PLOCK_MEMORY;
	LOCK_MEMORY pBuffer{ PID, Address, Size };

	INFO_STRUCT info{ CODE_LOCKMEMORY, &pBuffer, sizeof(LOCK_MEMORY) };

	DWORD Results = NtOpenFile((PHANDLE)&info, NULL, NULL, NULL, 0x20061128, 0x123456);

	if (Results == 状态_成功) return true;
	ERRORCODE = Results;
	return false;
}
