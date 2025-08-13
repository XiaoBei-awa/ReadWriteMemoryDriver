#include "Main.h"

typedef struct _PROTECTED_MEMORY_ENTRY {
    HANDLE ProcessId;
    PVOID VirtualAddress;
    PVOID OriginalData;
    SIZE_T Size;
    LIST_ENTRY ListEntry;
} PROTECTED_MEMORY_ENTRY, *PPROTECTED_MEMORY_ENTRY;

LIST_ENTRY g_ProtectedListHead;
KSPIN_LOCK g_ProtectedListLock;

// ��ʼ������
void InitializeMemoryProtection() 
{
    InitializeListHead(&g_ProtectedListHead);
    KeInitializeSpinLock(&g_ProtectedListLock);
}

// ������
void CleanupMemoryProtection() 
{
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&g_ProtectedListLock);

    while (!IsListEmpty(&g_ProtectedListHead)) {
        PLIST_ENTRY pEntry = RemoveHeadList(&g_ProtectedListHead);
        PPROTECTED_MEMORY_ENTRY pMemEntry = CONTAINING_RECORD(pEntry, PROTECTED_MEMORY_ENTRY, ListEntry);

        ExFreePool(pMemEntry->OriginalData);
        ExFreePool(pMemEntry);
    }

    KeReleaseSpinLock(&g_ProtectedListLock, irql);
}

// ����ܱ����ڴ�����
NTSTATUS AddMemoryToProtectedList(HANDLE ProcessId, PVOID VirtualAddress, SIZE_T Size)
{
    // ����ṹ��
    PPROTECTED_MEMORY_ENTRY pEntry = (PPROTECTED_MEMORY_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROTECTED_MEMORY_ENTRY), 'MPrT');
    if (!pEntry) return ״̬_����_�����ڴ�ʧ��;

    // ����ԭʼ���ݻ�����
    pEntry->OriginalData = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'OriD');
    if (!pEntry->OriginalData) 
    {
        ExFreePool(pEntry);
        return ״̬_����_�����ڴ�ʧ��;
    }

    // ��ȡ���̶���
    PEPROCESS cTargetProcess;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &cTargetProcess);
    if (!NT_SUCCESS(Status)) return ״̬_����_������Ч;

    // ���̹ҿ�
    KAPC_STATE APC{};
    KeStackAttachProcess(cTargetProcess, &APC);

    // ����ԭʼ����
    RtlCopyMemory(pEntry->OriginalData, VirtualAddress, Size);

    // ������̹ҿ�
    KeUnstackDetachProcess(&APC);

    // �ͷŽ��̶���
    ObDereferenceObject(cTargetProcess);

    // ���ṹ
    pEntry->ProcessId = ProcessId;
    pEntry->VirtualAddress = VirtualAddress;
    pEntry->Size = Size;

    // ��ӵ�ȫ������
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&g_ProtectedListLock);
    InsertTailList(&g_ProtectedListHead, &pEntry->ListEntry);
    KeReleaseSpinLock(&g_ProtectedListLock, irql);

    KdPrint(("[%s] ���̣�%d ��ӱ����ڴ�����0x%llX.", __FUNCTION__, (DWORD)ProcessId, (ULONG64)VirtualAddress));
    return ״̬_�ɹ�;
}

NTSTATUS MyNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
    NTSTATUS Status = OrgNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    if (!NT_SUCCESS(Status)) return Status;

    // ͨ�������ȡ����EPROCESS����
    PEPROCESS pProcess = NULL;
    NTSTATUS cStatus = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&pProcess, NULL);
    if (!NT_SUCCESS(cStatus)) return Status;

    // ��ȡ����PID
    HANDLE TargetProcessId = PsGetProcessId(pProcess);
    ObDereferenceObject(pProcess);
    if (!TargetProcessId) return Status;

    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&g_ProtectedListLock);

    // ���������б�
    PLIST_ENTRY pListEntry = g_ProtectedListHead.Flink;
    while (pListEntry != &g_ProtectedListHead)
    {
        PPROTECTED_MEMORY_ENTRY pEntry = CONTAINING_RECORD(pListEntry, PROTECTED_MEMORY_ENTRY, ListEntry);
        // ƥ�����ID
        if (pEntry->ProcessId == TargetProcessId)
        {
            // �����ڴ��ص�����
            ULONG64 ReadStart = (ULONG64)BaseAddress;
            ULONG64 ReadEnd = ReadStart + NumberOfBytesToRead;
            ULONG64 ProtectedStart = (ULONG64)pEntry->VirtualAddress;
            ULONG64 ProtectedEnd = ProtectedStart + pEntry->Size;

            if (ReadEnd > ProtectedStart && ReadStart < ProtectedEnd) {
                // �����ص�����
                ULONG64 OverlapStart = max(ReadStart, ProtectedStart);
                ULONG64 OverlapEnd = min(ReadEnd, ProtectedEnd);
                SIZE_T OverlapSize = OverlapEnd - OverlapStart;

                // ����ƫ����
                SIZE_T OffsetInProtected = OverlapStart - ProtectedStart;
                SIZE_T OffsetInBuffer = OverlapStart - ReadStart;

                // ��ԭʼ���ݸ��Ƕ�ȡ���
                RtlCopyMemory(
                    (PUCHAR)Buffer + OffsetInBuffer,
                    (PUCHAR)pEntry->OriginalData + OffsetInProtected,
                    OverlapSize);
            }
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_ProtectedListLock, irql);

	return Status;
}