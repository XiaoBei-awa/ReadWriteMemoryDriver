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

// 初始化函数
void InitializeMemoryProtection() 
{
    InitializeListHead(&g_ProtectedListHead);
    KeInitializeSpinLock(&g_ProtectedListLock);
}

// 清理函数
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

// 添加受保护内存区域
NTSTATUS AddMemoryToProtectedList(HANDLE ProcessId, PVOID VirtualAddress, SIZE_T Size)
{
    // 分配结构体
    PPROTECTED_MEMORY_ENTRY pEntry = (PPROTECTED_MEMORY_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROTECTED_MEMORY_ENTRY), 'MPrT');
    if (!pEntry) return 状态_错误_分配内存失败;

    // 分配原始数据缓冲区
    pEntry->OriginalData = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'OriD');
    if (!pEntry->OriginalData) 
    {
        ExFreePool(pEntry);
        return 状态_错误_分配内存失败;
    }

    // 获取进程对象
    PEPROCESS cTargetProcess;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &cTargetProcess);
    if (!NT_SUCCESS(Status)) return 状态_错误_进程无效;

    // 进程挂靠
    KAPC_STATE APC{};
    KeStackAttachProcess(cTargetProcess, &APC);

    // 保存原始数据
    RtlCopyMemory(pEntry->OriginalData, VirtualAddress, Size);

    // 解除进程挂靠
    KeUnstackDetachProcess(&APC);

    // 释放进程对象
    ObDereferenceObject(cTargetProcess);

    // 填充结构
    pEntry->ProcessId = ProcessId;
    pEntry->VirtualAddress = VirtualAddress;
    pEntry->Size = Size;

    // 添加到全局链表
    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&g_ProtectedListLock);
    InsertTailList(&g_ProtectedListHead, &pEntry->ListEntry);
    KeReleaseSpinLock(&g_ProtectedListLock, irql);

    KdPrint(("[%s] 进程：%d 添加保护内存区域：0x%llX.", __FUNCTION__, (DWORD)ProcessId, (ULONG64)VirtualAddress));
    return 状态_成功;
}

NTSTATUS MyNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
    NTSTATUS Status = OrgNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
    if (!NT_SUCCESS(Status)) return Status;

    // 通过句柄获取进程EPROCESS对象
    PEPROCESS pProcess = NULL;
    NTSTATUS cStatus = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&pProcess, NULL);
    if (!NT_SUCCESS(cStatus)) return Status;

    // 获取进程PID
    HANDLE TargetProcessId = PsGetProcessId(pProcess);
    ObDereferenceObject(pProcess);
    if (!TargetProcessId) return Status;

    KIRQL irql = KeAcquireSpinLockRaiseToDpc(&g_ProtectedListLock);

    // 遍历保护列表
    PLIST_ENTRY pListEntry = g_ProtectedListHead.Flink;
    while (pListEntry != &g_ProtectedListHead)
    {
        PPROTECTED_MEMORY_ENTRY pEntry = CONTAINING_RECORD(pListEntry, PROTECTED_MEMORY_ENTRY, ListEntry);
        // 匹配进程ID
        if (pEntry->ProcessId == TargetProcessId)
        {
            // 计算内存重叠区域
            ULONG64 ReadStart = (ULONG64)BaseAddress;
            ULONG64 ReadEnd = ReadStart + NumberOfBytesToRead;
            ULONG64 ProtectedStart = (ULONG64)pEntry->VirtualAddress;
            ULONG64 ProtectedEnd = ProtectedStart + pEntry->Size;

            if (ReadEnd > ProtectedStart && ReadStart < ProtectedEnd) {
                // 计算重叠区域
                ULONG64 OverlapStart = max(ReadStart, ProtectedStart);
                ULONG64 OverlapEnd = min(ReadEnd, ProtectedEnd);
                SIZE_T OverlapSize = OverlapEnd - OverlapStart;

                // 计算偏移量
                SIZE_T OffsetInProtected = OverlapStart - ProtectedStart;
                SIZE_T OffsetInBuffer = OverlapStart - ReadStart;

                // 用原始数据覆盖读取结果
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