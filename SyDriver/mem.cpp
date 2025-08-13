#include "Main.h"

// 路径转模块名
NTSTATUS StripPath(PUNICODE_STRING FilePath, PUNICODE_STRING FileName)
{

	INT32 Result = STATUS_UNSUCCESSFUL;

	for (USHORT i = (FilePath->Length / sizeof(WCHAR)) - 1; i != 0; i--) {

		if (FilePath->Buffer[i] == L'\\' || FilePath->Buffer[i] == L'/') {

			FileName->Buffer = &FilePath->Buffer[i + 1];

			FileName->Length = FileName->MaximumLength = FilePath->Length - (i + 1) * sizeof(WCHAR);

			Result = STATUS_SUCCESS;

			break;
		}
	}

	return Result;
}

// 效验CR3
bool IsValidCR3(ULONG64 cr3) {
	// 检查对齐（必须4KB对齐）
	if (cr3 & 0xFFF) return false;

	// 检查物理地址范围（通常52位以内）
	if (cr3 > 0x000FFFFFFFFFF000) return false;

	// 检查保留位（Intel规范：位63:52和MISC保留位必须为0）
	if (cr3 & 0xFFF0000000000F38) return false;

	return true;
}

// 挂靠取进程CR3，无视CR3加密
VOID SystemGetCR3(PCOPY_MEMORY SystemBuffer)
{
	// 进程挂靠
	KAPC_STATE APC{};
	KeStackAttachProcess(TargetProcess, &APC);

	// 读CR3
	ProcessCR3 = __readcr3();

	// 解除进程挂靠
	KeUnstackDetachProcess(&APC);

	if (IsValidCR3(ProcessCR3))
	{
		SystemBuffer->Status = 状态_成功;
		KdPrint(("[%s] 获取进程CR3成功: 0x%llx", __FUNCTION__, ProcessCR3));
	} else {
		SystemBuffer->Status = 状态_错误_CR3错误;
		KdPrint(("[%s] 获取进程CR3失败", __FUNCTION__));
	}

	KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
}

// 获取进程模块
VOID SystemGetModule(PCOPY_MEMORY SystemBuffer)
{
	PVOID Results = NULL;
	PVOID Current = NULL;
	typedef struct _GET_MODULE_BASE_BUFFER {
		PVOID ModuleNameBuffer;
		PVOID OutBuffer;
	} GET_MODULE_BASE_BUFFER, *PGET_MODULE_BASE_BUFFER;
	if (SystemBuffer->DataSize == sizeof(GET_MODULE_BASE_BUFFER))
	{
		GET_MODULE_BASE_BUFFER pBuffer = *(PGET_MODULE_BASE_BUFFER)SystemBuffer->Data;
		// InitUnicode
		UNICODE_STRING ModuleName;
		RtlInitUnicodeString(&ModuleName, (PCWSTR)pBuffer.ModuleNameBuffer);

		// 进程挂靠
		KAPC_STATE APC{};
		KeStackAttachProcess(TargetProcess, &APC);
		// 循环遍历
		do
		{
			MEMORY_BASIC_INFORMATION Mbi{};
			NTSTATUS Status = ZwQueryVirtualMemory(ZwCurrentProcess(), Current, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
			if (NT_SUCCESS(Status)) {
				if (Mbi.State == MEM_COMMIT && Mbi.Type == 0x1000000/*MEM_IMAGE*/) {
					struct {
						UNICODE_STRING Name;
						WCHAR Buffer[260];
					} SectionName;
					RtlZeroMemory(&SectionName, sizeof(SectionName)); // 初始化
					if (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Current, (MEMORY_INFORMATION_CLASS)(2), &SectionName, sizeof(SectionName), NULL))) {
						UNICODE_STRING CurrentModuleName;
						if (NT_SUCCESS(StripPath(&SectionName.Name, &CurrentModuleName))) {
							Results = RtlEqualUnicodeString(&CurrentModuleName, &ModuleName, TRUE) ? Current : NULL;
						}
					}
				}
				Current = (PVOID)((ULONGLONG)Mbi.BaseAddress + Mbi.RegionSize);
			} else {
				SystemBuffer->Status = 状态_错误_权限不足;
				break;
			}
				
		} while (Results == NULL);

		// 解除进程挂靠
		KeUnstackDetachProcess(&APC);

		KdPrint(("[%s] %ws模块句柄：%p.", __FUNCTION__, ModuleName.Buffer, Results));
		RtlCopyMemory(pBuffer.OutBuffer, &Results, sizeof(Results));
		SystemBuffer->Status = 状态_成功;
		KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
	} else {
		SystemBuffer->Status = 状态_错误_内部参数错误;
		KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
	}
}

// 分配内存
VOID SystemAllocMemory(PCOPY_MEMORY SystemBuffer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	typedef struct _ALLOC_MEMORY {
		PVOID Address;
		SIZE_T Size;
		PVOID OutBuffer;
	} ALLOC_MEMORY, *PALLOC_MEMORY;
	if (SystemBuffer->DataSize == sizeof(ALLOC_MEMORY))
	{
		ALLOC_MEMORY pBuffer = *(PALLOC_MEMORY)SystemBuffer->Data;

		// 进程挂靠
		KAPC_STATE APC{};
		KeStackAttachProcess(TargetProcess, &APC);
		// 分配虚拟内存
		PVOID BaseAddress = pBuffer.Address;  // 返回分配的内存地址 (如果不为NULL则在地址边界处分配区域)
		SIZE_T Length = pBuffer.Size;  // 返回实际分配的大小
		Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NT_SUCCESS(Status))
		{
			KdPrint(("[%s] 申请内存成功.", __FUNCTION__));
			RtlZeroMemory(BaseAddress, Length);  // 强制提交物理页，否则无法被TransformationCR3翻译
		}
		// 解除进程挂靠
		KeUnstackDetachProcess(&APC);
		// 返回数据
		RtlCopyMemory(pBuffer.OutBuffer, &BaseAddress, sizeof(BaseAddress));
	} else {
		SystemBuffer->Status = 状态_错误_内部参数错误;
		KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
	}

	SystemBuffer->Status = 状态_成功;
	KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
}

// 释放内存
VOID SystemFreeMemory(PCOPY_MEMORY SystemBuffer)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	typedef struct _FREE_MEMORY {
		PVOID Address;
		SIZE_T Size;
	} FREE_MEMORY, *PFREE_MEMORY;
	if (SystemBuffer->DataSize == sizeof(FREE_MEMORY))
	{
		FREE_MEMORY pBuffer = *(PFREE_MEMORY)SystemBuffer->Data;

		// 进程挂靠
		KAPC_STATE APC{};
		KeStackAttachProcess(TargetProcess, &APC);
		// 释放虚拟内存
		PVOID BaseAddress = pBuffer.Address;  // 待释放的虚拟内存地址
		SIZE_T Length = 0;  // 待释放区域的实际大小 (如果在FreeType参数中设置了MEM_RELEASE标志，则Length必须为零。ZwFreeVirtualMemory释放初始分配调用中保留的整个区域。)
		Status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &Length, MEM_RELEASE);
		if (NT_SUCCESS(Status))
		{
			KdPrint(("[%s] 释放内存成功.", __FUNCTION__));
		}
		// 解除进程挂靠
		KeUnstackDetachProcess(&APC);
	} else {
		SystemBuffer->Status = 状态_错误_内部参数错误;
		KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
	}

	SystemBuffer->Status = 状态_成功;
	KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
}

// 获取PTE基址
NTSTATUS GetPteBase() 
{
	// 获取PTE基地址
	ULONG64 Cr3 = __readcr3();
	PHYSICAL_ADDRESS DirectoryTableBase{};
	DirectoryTableBase.QuadPart = ((Cr3 >> 12) & 0xFFFFFFFFFFi64) << 12;// 去除控制位，拿到DirectoryTableBase
	PULONG64 PML4Table = (PULONG64)MmGetVirtualForPhysical(DirectoryTableBase);
	ULONG64 g_PteBase = 0;
	if (PML4Table)
	{
		ULONG64 Item = 0;
		for (ULONG64 index = 0; index < 0x200; ++index)
		{
			Item = PML4Table[index];
			if (((Item >> 12) & 0xFFFFFFFFFFi64) == ((Cr3 >> 12) & 0xFFFFFFFFFFi64))
			{
				g_PteBase = (index << 39) - 0x1000000000000;// + 0xFFFF000000000000
				KdPrint(("[%s] 获取到PteBase：0x%llX", __FUNCTION__, g_PteBase));
				break;
			}
		}
	}if (!g_PteBase){
		KdPrint(("[%s] 获取PTE基址失败.", __FUNCTION__));
		return STATUS_UNSUCCESSFUL;
	}
	PteBaseAddress = g_PteBase;
	return STATUS_SUCCESS;
}

// 挂物理页并刷新TLB读取物理内存
NTSTATUS ReadPhysicalAddress(PVOID PhysicalAddress, PVOID buffer, SIZE_T size)
{
	if (!PteBaseAddress)
	{
		if (!NT_SUCCESS(GetPteBase()))
		{
			KdPrint(("[%s] Pte基址错误.", __FUNCTION__));
			return 状态_错误_PTE基址错误;
		}
	}
	// 跨页访问先直接取消！！！
	if (((ULONG64)PhysicalAddress & 0xFFF) + size > 0x1000)
	{
		KdPrint(("[%s] 违规跨页访问，已取消.", __FUNCTION__));
		return 状态_取消_内存越界;
	}
	// 申请一页内存
	PVOID BaseAddress = MmAllocateMappingAddress(0x1000, 'smem');
	if (!BaseAddress) {
		KdPrint(("[%s] 申请内存失败.", __FUNCTION__));
		return 状态_错误_分配内存失败;
	}
	// 获取BaseAddress的PTE地址
	PVOID PteAddress = (PVOID)(PteBaseAddress + 8 * (((ULONG64)BaseAddress & 0xFFFFFFFFFFFFi64) >> 12));

	ULONG64 OldPte = *(ULONG64*)PteAddress;   // 保存原始页面PTE
	// 修改页面PTE改变映射关系
	*(ULONG64*)PteAddress = ((((ULONG64)PhysicalAddress >> 12) & 0xFFFFFFFFFFi64) << 12) | *(ULONG64*)PteAddress & 0xFFF0000000000EF8 | 0x103;
	__try
	{
		__invlpg(BaseAddress);	// 刷新TLB 让新的PTE生效
		RtlCopyMemory(buffer, (char*)BaseAddress + ((ULONG64)PhysicalAddress & 0xFFF), size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		*(ULONG64*)PteAddress = OldPte;  // 恢复原始页面PTE
		__invlpg(BaseAddress);	// 刷新TLB
		MmFreeMappingAddress(BaseAddress, 'smem');
		return 状态_错误_无法访问内存;
	}

	*(ULONG64*)PteAddress = OldPte;  // 恢复原始页面PTE
	__invlpg(BaseAddress);	// 刷新TLB
	MmFreeMappingAddress(BaseAddress, 'smem');
	return 状态_成功;
}

// 挂物理页并刷新TLB写入物理内存
NTSTATUS WritePhysicalAddress(PVOID PhysicalAddress, PVOID buffer, SIZE_T size)
{
	if (!PteBaseAddress)
	{
		if (!NT_SUCCESS(GetPteBase()))
		{
			KdPrint(("[%s] Pte基址错误.", __FUNCTION__));
			return 状态_错误_PTE基址错误;
		}
	}
	// 跨页访问先直接取消！！！
	if (((ULONG64)PhysicalAddress & 0xFFF) + size > 0x1000)
	{
		KdPrint(("[%s] 违规跨页访问，已取消.", __FUNCTION__));
		return 状态_取消_内存越界;
	}
	// 申请一页内存
	PVOID BaseAddress = MmAllocateMappingAddress(0x1000, 'smem');
	if (!BaseAddress) {
		KdPrint(("[%s] 申请内存失败.", __FUNCTION__));
		return 状态_错误_分配内存失败;
	}
	// 获取BaseAddress的PTE地址
	PVOID PteAddress = (PVOID)(PteBaseAddress + 8 * (((ULONG64)BaseAddress & 0xFFFFFFFFFFFFi64) >> 12));

	ULONG64 OldPte = *(ULONG64*)PteAddress;   // 保存原始页面PTE
	// 修改页面PTE改变映射关系
	*(ULONG64*)PteAddress = ((((ULONG64)PhysicalAddress >> 12) & 0xFFFFFFFFFFi64) << 12) | *(ULONG64*)PteAddress & 0xFFF0000000000EF8 | 0x103;
	__try
	{
		__invlpg(BaseAddress);	// 刷新TLB 让新的PTE生效
		RtlCopyMemory((char*)BaseAddress + ((ULONG64)PhysicalAddress & 0xFFF), buffer, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		*(ULONG64*)PteAddress = OldPte;  // 恢复原始页面PTE
		__invlpg(BaseAddress);	// 刷新TLB
		MmFreeMappingAddress(BaseAddress, 'smem');
		return 状态_错误_无法访问内存;
	}

	*(ULONG64*)PteAddress = OldPte;  // 恢复原始页面PTE
	__invlpg(BaseAddress);	// 刷新TLB
	MmFreeMappingAddress(BaseAddress, 'smem');
	return 状态_成功;
}

// 通过CR3翻译虚拟内存到物理内存
ULONG64 TransformationCR3(ULONG64 cr3, ULONG64 VirtualAddress)
{
	// 清除低4位
	cr3 &= ~0xf;
	// 获取页面偏移量
	ULONG64 PAGE_OFFSET = VirtualAddress & ~(~0ul << 12);

	// 读取虚拟地址所在的三级页表项
	ULONG64 a = 0, b = 0, c = 0;

	ReadPhysicalAddress((PVOID)(cr3 + 8 * ((VirtualAddress >> 39) & (0x1ffll))), &a, sizeof(a));

	// 如果 P（存在位）为0，表示该页表项没有映射物理内存，返回0
	if (~a & 1)
	{
		return 0;
	}

	// 读取虚拟地址所在的二级页表项
	ReadPhysicalAddress((PVOID)((a & ((~0xfull << 8) & 0xfffffffffull)) + 8 * ((VirtualAddress >> 30) & (0x1ffll))), &b, sizeof(b));

	// 如果 P 为0，表示该页表项没有映射物理内存，返回0
	if (~b & 1)
	{
		return 0;
	}

	// 如果 PS（页面大小）为1，表示该页表项映射的是1GB的物理内存，直接计算出物理地址并返回
	if (b & 0x80)
	{
		return (b & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));
	}

	// 读取虚拟地址所在的一级页表项
	ReadPhysicalAddress((PVOID)((b & ((~0xfull << 8) & 0xfffffffffull)) + 8 * ((VirtualAddress >> 21) & (0x1ffll))), &c, sizeof(c));

	// 如果 P 为0，表示该页表项没有映射物理内存，返回0
	if (~c & 1)
	{
		return 0;
	}
	// 如果 PS 为1，表示该页表项映射的是2MB的物理内存，直接计算出物理地址并返回
	if (c & 0x80)
	{
		return (c & ((~0xfull << 8) & 0xfffffffffull)) + (VirtualAddress & ~(~0ull << 21));
	}
	// 读取虚拟地址所在的零级页表项，计算出物理地址并返回
	ULONG64 address = 0;
	ReadPhysicalAddress((PVOID)((c & ((~0xfull << 8) & 0xfffffffffull)) + 8 * ((VirtualAddress >> 12) & (0x1ffll))), &address, sizeof(address));
	address &= ((~0xfull << 8) & 0xfffffffffull);
	if (!address)
	{
		return 0;
	}

	return address + PAGE_OFFSET;
}

NTSTATUS Memory::SetTargetProcess(HANDLE Processid)
{
	NTSTATUS 状态 = 0;
	NTSTATUS Status = PsLookupProcessByProcessId(Processid, &TargetProcess);

	if (NT_SUCCESS(Status))
	{
		ObDereferenceObject(TargetProcess);
		KdPrint(("[%s] 获取进程对象成功: %p", __FUNCTION__, TargetProcess));
		/* 获取进程CR3 */
		// 初始化事件
		COPY_MEMORY SystemBuffer{ NULL, NULL, NULL, NULL };
		KeInitializeEvent(&SystemBuffer.kEvent, SynchronizationEvent, FALSE);
		// 创建系统线程
		HANDLE hThread = 0;
		Status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)SystemGetCR3, &SystemBuffer);
		if (NT_SUCCESS(Status) && hThread)
		{
			KdPrint(("[%s] 创建内核线程成功.", __FUNCTION__));
			ZwClose(hThread);  // 关闭线程句柄
			KeWaitForSingleObject(&SystemBuffer.kEvent, Executive, KernelMode, TRUE, NULL);  // 等待事件
			状态 = SystemBuffer.Status;
		} else {
			状态 = 状态_错误_创建线程失败;
			KdPrint(("[%s] 创建内核线程失败.Status：%X", __FUNCTION__, Status));
		}
	} else {
		switch (Status)
		{
		case STATUS_NOT_FOUND:
		case STATUS_INVALID_CID:
		case STATUS_INVALID_PARAMETER:
		case STATUS_OBJECT_NAME_NOT_FOUND:
			状态 = 状态_错误_进程不存在;
			break;
		case STATUS_PROCESS_IS_TERMINATING:
			状态 = 状态_错误_进程已结束;
			break;
		case STATUS_ACCESS_DENIED:
			状态 = 状态_错误_权限不足;
			break;
		default:
			状态 = 状态_错误_未知;
			break;
		}
		KdPrint(("[%s] 获取进程对象失败.", __FUNCTION__));
	}

	if (状态 == 状态_错误_CR3错误)
	{
		// 重新获取进程CR3,可能被加密
		ProcessCR3 = *(PULONG64)((UCHAR*)TargetProcess + 0x28);
		if (IsValidCR3(ProcessCR3))
		{
			状态 = 状态_成功;
			KdPrint(("[%s] 重新获取进程CR3成功: 0x%llx", __FUNCTION__, ProcessCR3));
		} else {
			状态 = 状态_错误_CR3错误;
			KdPrint(("[%s] 重新获取进程CR3失败", __FUNCTION__));
		}
	}

	return 状态;
}

NTSTATUS Memory::ReadMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS 状态 = 0;
	// 判断目标进程是否有效
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] 目标进程无效.", __FUNCTION__));
		return 状态_错误_进程无效;
	}
	// 判断目标进程是否终止
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] 目标进程已结束.", __FUNCTION__));
		return 状态_错误_进程已结束;
	}
	// 虚拟地址到物理地址
	ULONG64 PhysicalAddress = TransformationCR3(ProcessCR3, Address);
	if (!PhysicalAddress) return 状态_错误_未映射物理内存;
	// 读物理地址
	if (Size <= 0x1000)
	{
		// 一页内读写
		状态 = ReadPhysicalAddress((PVOID)PhysicalAddress, Buffer, Size);
	} else {
		状态 = 状态_取消_内存过大;
	}

	return 状态;
}

NTSTATUS Memory::WriteMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	// 判断目标进程是否有效
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] 目标进程无效.", __FUNCTION__));
		return 状态_错误_进程无效;
	}
	// 判断目标进程是否终止
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] 目标进程已结束.", __FUNCTION__));
		return 状态_错误_进程已结束;
	}
	// 虚拟地址到物理地址
	ULONG64 PhysicalAddress = TransformationCR3(ProcessCR3, Address);
	if (!PhysicalAddress) return 状态_错误_未映射物理内存;

	// 写物理地址
	if (Size <= 0x1000)
	{
		// 一页内读写
		Status = WritePhysicalAddress((PVOID)PhysicalAddress, Buffer, Size);
	} else {
		Status = 状态_取消_内存过大;
	}

	return Status;
}

NTSTATUS Memory::GetModulebase(PVOID ModuleNameBuffer, PVOID Buffer)
{
	NTSTATUS 状态 = 0;
	// 判断目标进程是否有效
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] 目标进程无效.", __FUNCTION__));
		return 状态_错误_进程无效;
	}
	// 判断目标进程是否终止
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] 目标进程已结束.", __FUNCTION__));
		return 状态_错误_进程已结束;
	}
	
	// 创建MDL用于映射内存
	PMDL mdl = IoAllocateMdl(ModuleNameBuffer, 0x128, 0, 0, NULL);
	if (!mdl) return 状态_错误_MDL创建失败;
	MmBuildMdlForNonPagedPool(mdl);
	PVOID Map = MmMapLockedPages(mdl, KernelMode);
	if (!Map)
	{
		IoFreeMdl(mdl);
		return 状态_错误_MDL映射失败;
	}

	ULONG64 OutBuffer = 0;
	typedef struct _GET_MODULE_BASE_BUFFER {
		PVOID ModuleNameBuffer;
		PVOID OutBuffer;
	} GET_MODULE_BASE_BUFFER, *PGET_MODULE_BASE_BUFFER;
	GET_MODULE_BASE_BUFFER pBuffer{ Map, &OutBuffer };
	COPY_MEMORY SystemBuffer{ &pBuffer, sizeof(pBuffer), NULL, NULL };

	// 初始化事件
	KeInitializeEvent(&SystemBuffer.kEvent, SynchronizationEvent, FALSE);
	// 创建系统线程
	HANDLE hThread = 0;
	NTSTATUS Status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)SystemGetModule, &SystemBuffer);
	if (NT_SUCCESS(Status) && hThread)
	{
		KdPrint(("[%s] 创建内核线程成功.", __FUNCTION__));
		ZwClose(hThread);  // 关闭线程句柄
		KeWaitForSingleObject(&SystemBuffer.kEvent, Executive, KernelMode, TRUE, NULL);  // 等待事件
		状态 = SystemBuffer.Status;
	} else {
		状态 = 状态_错误_创建线程失败;
		KdPrint(("[%s] 创建内核线程失败. Status：%X", __FUNCTION__, Status));
	}
	// 释放MDL
	MmUnmapLockedPages(Map, mdl);
	IoFreeMdl(mdl);
	// 返回数据
	RtlCopyMemory((PVOID)Buffer, &OutBuffer, 8);

	return 状态;
}

NTSTATUS Memory::AllocMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS 状态 = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	// 判断目标进程是否有效
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] 目标进程无效.", __FUNCTION__));
		return 状态_错误_进程无效;
	}
	// 判断目标进程是否终止
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] 目标进程已结束.", __FUNCTION__));
		return 状态_错误_进程已结束;
	}
	
	ULONG64 OutBuffer = 0;
	typedef struct _ALLOC_MEMORY {
		PVOID Address;
		SIZE_T Size;
		PVOID OutBuffer;
	} ALLOC_MEMORY, *PALLOC_MEMORY;
	ALLOC_MEMORY pBuffer{ (PVOID)Address ,Size ,&OutBuffer };
	COPY_MEMORY SystemBuffer{ &pBuffer, sizeof(pBuffer), NULL, NULL };

	// 初始化事件
	KeInitializeEvent(&SystemBuffer.kEvent, SynchronizationEvent, FALSE);
	// 创建系统线程
	HANDLE hThread = 0;
	Status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)SystemAllocMemory, &SystemBuffer);
	if (NT_SUCCESS(Status) && hThread)
	{
		KdPrint(("[%s] 创建内核线程成功.", __FUNCTION__));
		ZwClose(hThread);  // 关闭线程句柄
		KeWaitForSingleObject(&SystemBuffer.kEvent, Executive, KernelMode, TRUE, NULL);  // 等待事件
		状态 = SystemBuffer.Status;
	} else {
		状态 = 状态_错误_创建线程失败;
		KdPrint(("[%s] 创建内核线程失败.Status：%X", __FUNCTION__, Status));
	}

	RtlCopyMemory(Buffer, &OutBuffer, 8);
	return 状态;
}

NTSTATUS Memory::FreeMemory(ULONG64 Address, SIZE_T Size)
{
	NTSTATUS 状态 = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	// 判断目标进程是否有效
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] 目标进程无效.", __FUNCTION__));
		return 状态_错误_进程无效;
	}
	// 判断目标进程是否终止
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] 目标进程已结束.", __FUNCTION__));
		return 状态_错误_进程已结束;
	}

	typedef struct _FREE_MEMORY {
		PVOID Address;
		SIZE_T Size;
	} FREE_MEMORY, *PFREE_MEMORY;
	FREE_MEMORY pBuffer{ (PVOID)Address ,Size };
	COPY_MEMORY SystemBuffer{ &pBuffer, sizeof(pBuffer), NULL, NULL };

	// 初始化事件
	KeInitializeEvent(&SystemBuffer.kEvent, SynchronizationEvent, FALSE);
	// 创建系统线程
	HANDLE hThread = 0;
	Status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)SystemFreeMemory, &SystemBuffer);
	if (NT_SUCCESS(Status) && hThread)
	{
		KdPrint(("[%s] 创建内核线程成功.", __FUNCTION__));
		ZwClose(hThread);  // 关闭线程句柄
		KeWaitForSingleObject(&SystemBuffer.kEvent, Executive, KernelMode, TRUE, NULL);  // 等待事件
		状态 = SystemBuffer.Status;
	} else {
		状态 = 状态_错误_创建线程失败;
		KdPrint(("[%s] 创建内核线程失败.Status：%X", __FUNCTION__, Status));
	}

	return 状态;
}
