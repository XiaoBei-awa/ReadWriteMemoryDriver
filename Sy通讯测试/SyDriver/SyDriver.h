#pragma once
#include <Windows.h>
#include <winternl.h>

#define 状态_成功 0x66666666
#define 状态_错误_IRQL 0xA0000001
#define 状态_错误_通讯不合法 0xA0000002
#define 状态_错误_参数不合法 0xA0000003
#define 状态_错误_进程不存在 0xA0000004
#define 状态_错误_进程已结束 0xA0000005
#define 状态_错误_进程无效 0xA0000006
#define 状态_错误_权限不足 0xA0000007
#define 状态_错误_MDL创建失败 0xA0000008
#define 状态_错误_MDL映射失败 0xA0000009
#define 状态_错误_创建线程失败 0xA000000A
#define 状态_错误_内部参数错误 0xA000000B
#define 状态_错误_未映射物理内存 0xA000000C
#define 状态_错误_PTE基址错误 0xA000000D
#define 状态_错误_分配内存失败 0xA000000E
#define 状态_错误_无法访问内存 0xA000000F
#define 状态_错误_未知 0xA0000010
#define 状态_取消_内存过大 0xA000000F
#define 状态_取消_内存越界 0xA0000020

#define CODE_CALLTEST '0000'
#define CODE_SETPROCESS '0001'
#define CODE_GETMODULEBASE '0002'
#define CODE_READMEMORY '0003'
#define CODE_WRITEMEMORY '0004'
#define CODE_ALLOCMEMORY '0005'
#define CODE_FREEMEMORY '0006'
#define CODE_LOCKMEMORY '0007'

// 通讯数据
typedef struct _INFO_STRUCT {
	ULONG Type;
	PVOID Data;
	ULONG DataSize;
}INFO_STRUCT, *PINFO_STRUCT;

extern DWORD ERRORCODE;  //	保存上一个错误信息

namespace SyDriver
{
	bool CallTest();
	bool SetTargetProcess(HANDLE PID);
	DWORD64 GetModuleBase(const wchar_t* ModuleName);
	bool ReadMemory(DWORD64 Address, PVOID Buffer, size_t Size);
	bool WriteMemory(DWORD64 Address, PVOID Buffer, size_t Size);
	bool AllocMemory(DWORD64 Address, PVOID Buffer, size_t Size);
	bool FreeMemory(DWORD64 Address, size_t Size);
	bool LockMemoryR3(HANDLE PID, DWORD64 Address, size_t Size);
}