#pragma once
#include <Windows.h>
#include <winternl.h>

#define ״̬_�ɹ� 0x66666666
#define ״̬_����_IRQL 0xA0000001
#define ״̬_����_ͨѶ���Ϸ� 0xA0000002
#define ״̬_����_�������Ϸ� 0xA0000003
#define ״̬_����_���̲����� 0xA0000004
#define ״̬_����_�����ѽ��� 0xA0000005
#define ״̬_����_������Ч 0xA0000006
#define ״̬_����_Ȩ�޲��� 0xA0000007
#define ״̬_����_MDL����ʧ�� 0xA0000008
#define ״̬_����_MDLӳ��ʧ�� 0xA0000009
#define ״̬_����_�����߳�ʧ�� 0xA000000A
#define ״̬_����_�ڲ��������� 0xA000000B
#define ״̬_����_δӳ�������ڴ� 0xA000000C
#define ״̬_����_PTE��ַ���� 0xA000000D
#define ״̬_����_�����ڴ�ʧ�� 0xA000000E
#define ״̬_����_�޷������ڴ� 0xA000000F
#define ״̬_����_δ֪ 0xA0000010
#define ״̬_ȡ��_�ڴ���� 0xA000000F
#define ״̬_ȡ��_�ڴ�Խ�� 0xA0000020

#define CODE_CALLTEST '0000'
#define CODE_SETPROCESS '0001'
#define CODE_GETMODULEBASE '0002'
#define CODE_READMEMORY '0003'
#define CODE_WRITEMEMORY '0004'
#define CODE_ALLOCMEMORY '0005'
#define CODE_FREEMEMORY '0006'
#define CODE_LOCKMEMORY '0007'

// ͨѶ����
typedef struct _INFO_STRUCT {
	ULONG Type;
	PVOID Data;
	ULONG DataSize;
}INFO_STRUCT, *PINFO_STRUCT;

extern DWORD ERRORCODE;  //	������һ��������Ϣ

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