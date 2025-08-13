#include "Main.h"

pfNtOpenFile OrgNtOpenFile = NULL;
pfNtReadVirtualMemory OrgNtReadVirtualMemory = NULL;

NTSTATUS MyNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
	if (ShareAccess == 0x20061128 && OpenOptions == 0x123456)
	{
		// �ж�IRQL�ȼ�,����PASSIVE_LEVEL�򷵻ش���,����һЩ�ں�API�޷����������ڴ����������
		if (KeGetCurrentIrql() != PASSIVE_LEVEL) return ״̬_����_IRQL;

		// ��ȡͨѶ����
		PINFO_STRUCT info = reinterpret_cast<PINFO_STRUCT>(FileHandle);

		switch (info->Type)
		{
		case '0000': // ͨѶ����
            return ״̬_�ɹ�;
		case '0001': // ���ý���
            typedef struct _SETPROCESS
            {
                HANDLE PID;
            } SETPROCESS, *PSETPROCESS;
            if (info->DataSize == sizeof(SETPROCESS))
            {
                SETPROCESS pBuffer = *(PSETPROCESS)info->Data;
                if ((DWORD64)pBuffer.PID < 1) return ״̬_����_�������Ϸ�;

                NTSTATUS ״̬ = Memory::SetTargetProcess(pBuffer.PID);
                return ״̬;
            }
			break;
        case '0002': // ��ȡģ��
            typedef struct _GET_MODULE_BASE_BUFFER {
                PVOID ModuleNameBuffer;
                PVOID OutBuffer;
            } GET_MODULE_BASE_BUFFER, * PGET_MODULE_BASE_BUFFER;
            if (info->DataSize == sizeof(GET_MODULE_BASE_BUFFER))
            {
                GET_MODULE_BASE_BUFFER pBuffer = *(PGET_MODULE_BASE_BUFFER)info->Data;
                if (pBuffer.ModuleNameBuffer == nullptr || pBuffer.OutBuffer == nullptr) return ״̬_����_�������Ϸ�;

                NTSTATUS ״̬ = Memory::GetModulebase(pBuffer.ModuleNameBuffer, pBuffer.OutBuffer);
                return ״̬;
            }
            break;
        case '0003': // ���ڴ�
            typedef struct _READ_MEMORY
            {
                ULONG64 Address;
                PVOID Buffer;
                SIZE_T Size;
            } READ_MEMORY, *PREAD_MEMORY;
            if (info->DataSize == sizeof(READ_MEMORY))
            {
                READ_MEMORY pBuffer = *(PREAD_MEMORY)info->Data;
                if (pBuffer.Address == 0 || pBuffer.Buffer == 0 || pBuffer.Size == 0) return ״̬_����_�������Ϸ�;

                NTSTATUS ״̬ = Memory::ReadMemory(pBuffer.Address, pBuffer.Buffer, pBuffer.Size);
                return ״̬;
            }
            break;
        case '0004': // д�ڴ�
            typedef struct _WRITE_MEMORY
            {
                ULONG64 Address;
                PVOID Buffer;
                SIZE_T Size;
            } WRITE_MEMORY, *PWRITE_MEMORY;
            if (info->DataSize == sizeof(WRITE_MEMORY))
            {
                WRITE_MEMORY pBuffer = *(PWRITE_MEMORY)info->Data;
                if (pBuffer.Address == 0 || pBuffer.Buffer == 0 || pBuffer.Size == 0) return ״̬_����_�������Ϸ�;

                NTSTATUS ״̬ = Memory::WriteMemory(pBuffer.Address, pBuffer.Buffer, pBuffer.Size);
                return ״̬;
            }
            break;
        case '0005': // �����ڴ�
            typedef struct _ALLOC_MEMORY {
                ULONG64 Address;
                PVOID Buffer;
                SIZE_T Size;
            } ALLOC_MEMORY, *PALLOC_MEMORY;
            if (info->DataSize == sizeof(ALLOC_MEMORY))
            {
                ALLOC_MEMORY pBuffer = *(PALLOC_MEMORY)info->Data;
                if (pBuffer.Buffer == 0) return ״̬_����_�������Ϸ�;

                NTSTATUS ״̬ = Memory::AllocMemory(pBuffer.Address, pBuffer.Buffer, pBuffer.Size);
                return ״̬;
            }
            break;
        case '0006': // �ͷ��ڴ�
            typedef struct _FREE_MEMORY {
                ULONG64 Address;
                SIZE_T Size;
            } FREE_MEMORY, *PFREE_MEMORY;
            if (info->DataSize == sizeof(FREE_MEMORY))
            {
                FREE_MEMORY pBuffer = *(PFREE_MEMORY)info->Data;
                if (pBuffer.Address == 0) return ״̬_����_�������Ϸ�;

                NTSTATUS ״̬ = Memory::FreeMemory(pBuffer.Address, pBuffer.Size);
                return ״̬;
            }
            break;
        case '0007': // R3�ڴ���������
            typedef struct _LOCK_MEMORY
            {
                HANDLE PID;
                ULONG64 Address;
                SIZE_T Size;
            }LOCK_MEMORY, *PLOCK_MEMORY;
            if (info->DataSize == sizeof(LOCK_MEMORY))
            {
                LOCK_MEMORY pBuffer = *(PLOCK_MEMORY)info->Data;
                if (pBuffer.PID == 0 || pBuffer.Address == 0 || pBuffer.Size == 0) return ״̬_����_�������Ϸ�;

                NTSTATUS ״̬ = AddMemoryToProtectedList(pBuffer.PID, (PVOID)pBuffer.Address, pBuffer.Size);
                return ״̬;
            }
            break;
        default:
            break;
		}

        KdPrint(("[%s] ͨѶ���Ϸ�.", __FUNCTION__));
		return ״̬_����_ͨѶ���Ϸ�;
	}
	return OrgNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

BOOLEAN __fastcall GetCallIndex()
{
    NTOS_VERSION osver = GetSystemInfo();

    if (osver == NTOS_WIN10_1507)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN10_1511)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN10_1607)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN10_1703)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN10_1803)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN10_1809)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN10_1903)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN10_1909)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN10_20H1 || osver == NTOS_WIN10_20H2 || osver == NTOS_WIN10_21H1 || osver == NTOS_WIN10_21H2 || osver == NTOS_WIN10_22H2)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WINSERVER_2022)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN11_21H2)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN11_22H2)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN11_23H2)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN11_24H2)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN11_25H2A)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }
    if (osver == NTOS_WIN11_25H2B)
    {
        CallIndexNtOpenFile = 51;
        CallIndexNtReadVirtualMemory = 63;
    }

    if (osver == NTOS_UNKNOWN) return FALSE;
    return TRUE;
}

void __fastcall InfinityCallback(unsigned long nCallIndex, PVOID* pSsdtAddress)
{
	if (nCallIndex)
	{
		if (nCallIndex == CallIndexNtOpenFile) {
			if (!OrgNtOpenFile) OrgNtOpenFile = (pfNtOpenFile)*pSsdtAddress;
			*pSsdtAddress = MyNtOpenFile;
		}
        if (nCallIndex == CallIndexNtReadVirtualMemory) {
            if (!OrgNtReadVirtualMemory) OrgNtReadVirtualMemory = (pfNtReadVirtualMemory)*pSsdtAddress;
            *pSsdtAddress = MyNtReadVirtualMemory;
        }

    } if (!CallIndexNtOpenFile)
    {
        if (GetCallIndex())
        {
            KdPrint(("[%s] ��ȡCallIndex�ɹ�.", __FUNCTION__));
        }
    } 
}
