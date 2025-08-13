#pragma once
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
#define 状态_错误_CR3错误 0xA0000010
#define 状态_错误_未知 0xA0000020
#define 状态_取消_内存过大 0xA0000021
#define 状态_取消_内存越界 0xA0000022

// 通讯数据
typedef struct _INFO_STRUCT {
	ULONG Type;
	PVOID Data;
	ULONG DataSize;
}INFO_STRUCT, *PINFO_STRUCT;

typedef NTSTATUS(__fastcall* pfNtOpenFile)(_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_ ULONG ShareAccess,
	_In_ ULONG OpenOptions);
typedef NTSTATUS(__fastcall* pfNtReadVirtualMemory)(_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToRead,
	_Out_opt_ PSIZE_T NumberOfBytesRead);

extern pfNtOpenFile OrgNtOpenFile;
extern pfNtReadVirtualMemory OrgNtReadVirtualMemory;

static ULONG CallIndexNtOpenFile = 0;
static ULONG CallIndexNtReadVirtualMemory = 0;

void __fastcall InfinityCallback(unsigned long nCallIndex, PVOID* pSsdtAddress);