#pragma once
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
#define ״̬_����_CR3���� 0xA0000010
#define ״̬_����_δ֪ 0xA0000020
#define ״̬_ȡ��_�ڴ���� 0xA0000021
#define ״̬_ȡ��_�ڴ�Խ�� 0xA0000022

// ͨѶ����
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