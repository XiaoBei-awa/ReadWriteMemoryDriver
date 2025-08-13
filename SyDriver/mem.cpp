#include "Main.h"

// ·��תģ����
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

// Ч��CR3
bool IsValidCR3(ULONG64 cr3) {
	// �����루����4KB���룩
	if (cr3 & 0xFFF) return false;

	// ��������ַ��Χ��ͨ��52λ���ڣ�
	if (cr3 > 0x000FFFFFFFFFF000) return false;

	// ��鱣��λ��Intel�淶��λ63:52��MISC����λ����Ϊ0��
	if (cr3 & 0xFFF0000000000F38) return false;

	return true;
}

// �ҿ�ȡ����CR3������CR3����
VOID SystemGetCR3(PCOPY_MEMORY SystemBuffer)
{
	// ���̹ҿ�
	KAPC_STATE APC{};
	KeStackAttachProcess(TargetProcess, &APC);

	// ��CR3
	ProcessCR3 = __readcr3();

	// ������̹ҿ�
	KeUnstackDetachProcess(&APC);

	if (IsValidCR3(ProcessCR3))
	{
		SystemBuffer->Status = ״̬_�ɹ�;
		KdPrint(("[%s] ��ȡ����CR3�ɹ�: 0x%llx", __FUNCTION__, ProcessCR3));
	} else {
		SystemBuffer->Status = ״̬_����_CR3����;
		KdPrint(("[%s] ��ȡ����CR3ʧ��", __FUNCTION__));
	}

	KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
}

// ��ȡ����ģ��
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

		// ���̹ҿ�
		KAPC_STATE APC{};
		KeStackAttachProcess(TargetProcess, &APC);
		// ѭ������
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
					RtlZeroMemory(&SectionName, sizeof(SectionName)); // ��ʼ��
					if (NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Current, (MEMORY_INFORMATION_CLASS)(2), &SectionName, sizeof(SectionName), NULL))) {
						UNICODE_STRING CurrentModuleName;
						if (NT_SUCCESS(StripPath(&SectionName.Name, &CurrentModuleName))) {
							Results = RtlEqualUnicodeString(&CurrentModuleName, &ModuleName, TRUE) ? Current : NULL;
						}
					}
				}
				Current = (PVOID)((ULONGLONG)Mbi.BaseAddress + Mbi.RegionSize);
			} else {
				SystemBuffer->Status = ״̬_����_Ȩ�޲���;
				break;
			}
				
		} while (Results == NULL);

		// ������̹ҿ�
		KeUnstackDetachProcess(&APC);

		KdPrint(("[%s] %wsģ������%p.", __FUNCTION__, ModuleName.Buffer, Results));
		RtlCopyMemory(pBuffer.OutBuffer, &Results, sizeof(Results));
		SystemBuffer->Status = ״̬_�ɹ�;
		KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
	} else {
		SystemBuffer->Status = ״̬_����_�ڲ���������;
		KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
	}
}

// �����ڴ�
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

		// ���̹ҿ�
		KAPC_STATE APC{};
		KeStackAttachProcess(TargetProcess, &APC);
		// ���������ڴ�
		PVOID BaseAddress = pBuffer.Address;  // ���ط�����ڴ��ַ (�����ΪNULL���ڵ�ַ�߽紦��������)
		SIZE_T Length = pBuffer.Size;  // ����ʵ�ʷ���Ĵ�С
		Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NT_SUCCESS(Status))
		{
			KdPrint(("[%s] �����ڴ�ɹ�.", __FUNCTION__));
			RtlZeroMemory(BaseAddress, Length);  // ǿ���ύ����ҳ�������޷���TransformationCR3����
		}
		// ������̹ҿ�
		KeUnstackDetachProcess(&APC);
		// ��������
		RtlCopyMemory(pBuffer.OutBuffer, &BaseAddress, sizeof(BaseAddress));
	} else {
		SystemBuffer->Status = ״̬_����_�ڲ���������;
		KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
	}

	SystemBuffer->Status = ״̬_�ɹ�;
	KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
}

// �ͷ��ڴ�
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

		// ���̹ҿ�
		KAPC_STATE APC{};
		KeStackAttachProcess(TargetProcess, &APC);
		// �ͷ������ڴ�
		PVOID BaseAddress = pBuffer.Address;  // ���ͷŵ������ڴ��ַ
		SIZE_T Length = 0;  // ���ͷ������ʵ�ʴ�С (�����FreeType������������MEM_RELEASE��־����Length����Ϊ�㡣ZwFreeVirtualMemory�ͷų�ʼ��������б�������������)
		Status = ZwFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &Length, MEM_RELEASE);
		if (NT_SUCCESS(Status))
		{
			KdPrint(("[%s] �ͷ��ڴ�ɹ�.", __FUNCTION__));
		}
		// ������̹ҿ�
		KeUnstackDetachProcess(&APC);
	} else {
		SystemBuffer->Status = ״̬_����_�ڲ���������;
		KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
	}

	SystemBuffer->Status = ״̬_�ɹ�;
	KeSetEvent(&SystemBuffer->kEvent, 0, TRUE);
}

// ��ȡPTE��ַ
NTSTATUS GetPteBase() 
{
	// ��ȡPTE����ַ
	ULONG64 Cr3 = __readcr3();
	PHYSICAL_ADDRESS DirectoryTableBase{};
	DirectoryTableBase.QuadPart = ((Cr3 >> 12) & 0xFFFFFFFFFFi64) << 12;// ȥ������λ���õ�DirectoryTableBase
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
				KdPrint(("[%s] ��ȡ��PteBase��0x%llX", __FUNCTION__, g_PteBase));
				break;
			}
		}
	}if (!g_PteBase){
		KdPrint(("[%s] ��ȡPTE��ַʧ��.", __FUNCTION__));
		return STATUS_UNSUCCESSFUL;
	}
	PteBaseAddress = g_PteBase;
	return STATUS_SUCCESS;
}

// ������ҳ��ˢ��TLB��ȡ�����ڴ�
NTSTATUS ReadPhysicalAddress(PVOID PhysicalAddress, PVOID buffer, SIZE_T size)
{
	if (!PteBaseAddress)
	{
		if (!NT_SUCCESS(GetPteBase()))
		{
			KdPrint(("[%s] Pte��ַ����.", __FUNCTION__));
			return ״̬_����_PTE��ַ����;
		}
	}
	// ��ҳ������ֱ��ȡ��������
	if (((ULONG64)PhysicalAddress & 0xFFF) + size > 0x1000)
	{
		KdPrint(("[%s] Υ���ҳ���ʣ���ȡ��.", __FUNCTION__));
		return ״̬_ȡ��_�ڴ�Խ��;
	}
	// ����һҳ�ڴ�
	PVOID BaseAddress = MmAllocateMappingAddress(0x1000, 'smem');
	if (!BaseAddress) {
		KdPrint(("[%s] �����ڴ�ʧ��.", __FUNCTION__));
		return ״̬_����_�����ڴ�ʧ��;
	}
	// ��ȡBaseAddress��PTE��ַ
	PVOID PteAddress = (PVOID)(PteBaseAddress + 8 * (((ULONG64)BaseAddress & 0xFFFFFFFFFFFFi64) >> 12));

	ULONG64 OldPte = *(ULONG64*)PteAddress;   // ����ԭʼҳ��PTE
	// �޸�ҳ��PTE�ı�ӳ���ϵ
	*(ULONG64*)PteAddress = ((((ULONG64)PhysicalAddress >> 12) & 0xFFFFFFFFFFi64) << 12) | *(ULONG64*)PteAddress & 0xFFF0000000000EF8 | 0x103;
	__try
	{
		__invlpg(BaseAddress);	// ˢ��TLB ���µ�PTE��Ч
		RtlCopyMemory(buffer, (char*)BaseAddress + ((ULONG64)PhysicalAddress & 0xFFF), size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		*(ULONG64*)PteAddress = OldPte;  // �ָ�ԭʼҳ��PTE
		__invlpg(BaseAddress);	// ˢ��TLB
		MmFreeMappingAddress(BaseAddress, 'smem');
		return ״̬_����_�޷������ڴ�;
	}

	*(ULONG64*)PteAddress = OldPte;  // �ָ�ԭʼҳ��PTE
	__invlpg(BaseAddress);	// ˢ��TLB
	MmFreeMappingAddress(BaseAddress, 'smem');
	return ״̬_�ɹ�;
}

// ������ҳ��ˢ��TLBд�������ڴ�
NTSTATUS WritePhysicalAddress(PVOID PhysicalAddress, PVOID buffer, SIZE_T size)
{
	if (!PteBaseAddress)
	{
		if (!NT_SUCCESS(GetPteBase()))
		{
			KdPrint(("[%s] Pte��ַ����.", __FUNCTION__));
			return ״̬_����_PTE��ַ����;
		}
	}
	// ��ҳ������ֱ��ȡ��������
	if (((ULONG64)PhysicalAddress & 0xFFF) + size > 0x1000)
	{
		KdPrint(("[%s] Υ���ҳ���ʣ���ȡ��.", __FUNCTION__));
		return ״̬_ȡ��_�ڴ�Խ��;
	}
	// ����һҳ�ڴ�
	PVOID BaseAddress = MmAllocateMappingAddress(0x1000, 'smem');
	if (!BaseAddress) {
		KdPrint(("[%s] �����ڴ�ʧ��.", __FUNCTION__));
		return ״̬_����_�����ڴ�ʧ��;
	}
	// ��ȡBaseAddress��PTE��ַ
	PVOID PteAddress = (PVOID)(PteBaseAddress + 8 * (((ULONG64)BaseAddress & 0xFFFFFFFFFFFFi64) >> 12));

	ULONG64 OldPte = *(ULONG64*)PteAddress;   // ����ԭʼҳ��PTE
	// �޸�ҳ��PTE�ı�ӳ���ϵ
	*(ULONG64*)PteAddress = ((((ULONG64)PhysicalAddress >> 12) & 0xFFFFFFFFFFi64) << 12) | *(ULONG64*)PteAddress & 0xFFF0000000000EF8 | 0x103;
	__try
	{
		__invlpg(BaseAddress);	// ˢ��TLB ���µ�PTE��Ч
		RtlCopyMemory((char*)BaseAddress + ((ULONG64)PhysicalAddress & 0xFFF), buffer, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		*(ULONG64*)PteAddress = OldPte;  // �ָ�ԭʼҳ��PTE
		__invlpg(BaseAddress);	// ˢ��TLB
		MmFreeMappingAddress(BaseAddress, 'smem');
		return ״̬_����_�޷������ڴ�;
	}

	*(ULONG64*)PteAddress = OldPte;  // �ָ�ԭʼҳ��PTE
	__invlpg(BaseAddress);	// ˢ��TLB
	MmFreeMappingAddress(BaseAddress, 'smem');
	return ״̬_�ɹ�;
}

// ͨ��CR3���������ڴ浽�����ڴ�
ULONG64 TransformationCR3(ULONG64 cr3, ULONG64 VirtualAddress)
{
	// �����4λ
	cr3 &= ~0xf;
	// ��ȡҳ��ƫ����
	ULONG64 PAGE_OFFSET = VirtualAddress & ~(~0ul << 12);

	// ��ȡ�����ַ���ڵ�����ҳ����
	ULONG64 a = 0, b = 0, c = 0;

	ReadPhysicalAddress((PVOID)(cr3 + 8 * ((VirtualAddress >> 39) & (0x1ffll))), &a, sizeof(a));

	// ��� P������λ��Ϊ0����ʾ��ҳ����û��ӳ�������ڴ棬����0
	if (~a & 1)
	{
		return 0;
	}

	// ��ȡ�����ַ���ڵĶ���ҳ����
	ReadPhysicalAddress((PVOID)((a & ((~0xfull << 8) & 0xfffffffffull)) + 8 * ((VirtualAddress >> 30) & (0x1ffll))), &b, sizeof(b));

	// ��� P Ϊ0����ʾ��ҳ����û��ӳ�������ڴ棬����0
	if (~b & 1)
	{
		return 0;
	}

	// ��� PS��ҳ���С��Ϊ1����ʾ��ҳ����ӳ�����1GB�������ڴ棬ֱ�Ӽ���������ַ������
	if (b & 0x80)
	{
		return (b & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));
	}

	// ��ȡ�����ַ���ڵ�һ��ҳ����
	ReadPhysicalAddress((PVOID)((b & ((~0xfull << 8) & 0xfffffffffull)) + 8 * ((VirtualAddress >> 21) & (0x1ffll))), &c, sizeof(c));

	// ��� P Ϊ0����ʾ��ҳ����û��ӳ�������ڴ棬����0
	if (~c & 1)
	{
		return 0;
	}
	// ��� PS Ϊ1����ʾ��ҳ����ӳ�����2MB�������ڴ棬ֱ�Ӽ���������ַ������
	if (c & 0x80)
	{
		return (c & ((~0xfull << 8) & 0xfffffffffull)) + (VirtualAddress & ~(~0ull << 21));
	}
	// ��ȡ�����ַ���ڵ��㼶ҳ�������������ַ������
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
	NTSTATUS ״̬ = 0;
	NTSTATUS Status = PsLookupProcessByProcessId(Processid, &TargetProcess);

	if (NT_SUCCESS(Status))
	{
		ObDereferenceObject(TargetProcess);
		KdPrint(("[%s] ��ȡ���̶���ɹ�: %p", __FUNCTION__, TargetProcess));
		/* ��ȡ����CR3 */
		// ��ʼ���¼�
		COPY_MEMORY SystemBuffer{ NULL, NULL, NULL, NULL };
		KeInitializeEvent(&SystemBuffer.kEvent, SynchronizationEvent, FALSE);
		// ����ϵͳ�߳�
		HANDLE hThread = 0;
		Status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)SystemGetCR3, &SystemBuffer);
		if (NT_SUCCESS(Status) && hThread)
		{
			KdPrint(("[%s] �����ں��̳߳ɹ�.", __FUNCTION__));
			ZwClose(hThread);  // �ر��߳̾��
			KeWaitForSingleObject(&SystemBuffer.kEvent, Executive, KernelMode, TRUE, NULL);  // �ȴ��¼�
			״̬ = SystemBuffer.Status;
		} else {
			״̬ = ״̬_����_�����߳�ʧ��;
			KdPrint(("[%s] �����ں��߳�ʧ��.Status��%X", __FUNCTION__, Status));
		}
	} else {
		switch (Status)
		{
		case STATUS_NOT_FOUND:
		case STATUS_INVALID_CID:
		case STATUS_INVALID_PARAMETER:
		case STATUS_OBJECT_NAME_NOT_FOUND:
			״̬ = ״̬_����_���̲�����;
			break;
		case STATUS_PROCESS_IS_TERMINATING:
			״̬ = ״̬_����_�����ѽ���;
			break;
		case STATUS_ACCESS_DENIED:
			״̬ = ״̬_����_Ȩ�޲���;
			break;
		default:
			״̬ = ״̬_����_δ֪;
			break;
		}
		KdPrint(("[%s] ��ȡ���̶���ʧ��.", __FUNCTION__));
	}

	if (״̬ == ״̬_����_CR3����)
	{
		// ���»�ȡ����CR3,���ܱ�����
		ProcessCR3 = *(PULONG64)((UCHAR*)TargetProcess + 0x28);
		if (IsValidCR3(ProcessCR3))
		{
			״̬ = ״̬_�ɹ�;
			KdPrint(("[%s] ���»�ȡ����CR3�ɹ�: 0x%llx", __FUNCTION__, ProcessCR3));
		} else {
			״̬ = ״̬_����_CR3����;
			KdPrint(("[%s] ���»�ȡ����CR3ʧ��", __FUNCTION__));
		}
	}

	return ״̬;
}

NTSTATUS Memory::ReadMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS ״̬ = 0;
	// �ж�Ŀ������Ƿ���Ч
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] Ŀ�������Ч.", __FUNCTION__));
		return ״̬_����_������Ч;
	}
	// �ж�Ŀ������Ƿ���ֹ
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] Ŀ������ѽ���.", __FUNCTION__));
		return ״̬_����_�����ѽ���;
	}
	// �����ַ�������ַ
	ULONG64 PhysicalAddress = TransformationCR3(ProcessCR3, Address);
	if (!PhysicalAddress) return ״̬_����_δӳ�������ڴ�;
	// �������ַ
	if (Size <= 0x1000)
	{
		// һҳ�ڶ�д
		״̬ = ReadPhysicalAddress((PVOID)PhysicalAddress, Buffer, Size);
	} else {
		״̬ = ״̬_ȡ��_�ڴ����;
	}

	return ״̬;
}

NTSTATUS Memory::WriteMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	// �ж�Ŀ������Ƿ���Ч
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] Ŀ�������Ч.", __FUNCTION__));
		return ״̬_����_������Ч;
	}
	// �ж�Ŀ������Ƿ���ֹ
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] Ŀ������ѽ���.", __FUNCTION__));
		return ״̬_����_�����ѽ���;
	}
	// �����ַ�������ַ
	ULONG64 PhysicalAddress = TransformationCR3(ProcessCR3, Address);
	if (!PhysicalAddress) return ״̬_����_δӳ�������ڴ�;

	// д�����ַ
	if (Size <= 0x1000)
	{
		// һҳ�ڶ�д
		Status = WritePhysicalAddress((PVOID)PhysicalAddress, Buffer, Size);
	} else {
		Status = ״̬_ȡ��_�ڴ����;
	}

	return Status;
}

NTSTATUS Memory::GetModulebase(PVOID ModuleNameBuffer, PVOID Buffer)
{
	NTSTATUS ״̬ = 0;
	// �ж�Ŀ������Ƿ���Ч
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] Ŀ�������Ч.", __FUNCTION__));
		return ״̬_����_������Ч;
	}
	// �ж�Ŀ������Ƿ���ֹ
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] Ŀ������ѽ���.", __FUNCTION__));
		return ״̬_����_�����ѽ���;
	}
	
	// ����MDL����ӳ���ڴ�
	PMDL mdl = IoAllocateMdl(ModuleNameBuffer, 0x128, 0, 0, NULL);
	if (!mdl) return ״̬_����_MDL����ʧ��;
	MmBuildMdlForNonPagedPool(mdl);
	PVOID Map = MmMapLockedPages(mdl, KernelMode);
	if (!Map)
	{
		IoFreeMdl(mdl);
		return ״̬_����_MDLӳ��ʧ��;
	}

	ULONG64 OutBuffer = 0;
	typedef struct _GET_MODULE_BASE_BUFFER {
		PVOID ModuleNameBuffer;
		PVOID OutBuffer;
	} GET_MODULE_BASE_BUFFER, *PGET_MODULE_BASE_BUFFER;
	GET_MODULE_BASE_BUFFER pBuffer{ Map, &OutBuffer };
	COPY_MEMORY SystemBuffer{ &pBuffer, sizeof(pBuffer), NULL, NULL };

	// ��ʼ���¼�
	KeInitializeEvent(&SystemBuffer.kEvent, SynchronizationEvent, FALSE);
	// ����ϵͳ�߳�
	HANDLE hThread = 0;
	NTSTATUS Status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)SystemGetModule, &SystemBuffer);
	if (NT_SUCCESS(Status) && hThread)
	{
		KdPrint(("[%s] �����ں��̳߳ɹ�.", __FUNCTION__));
		ZwClose(hThread);  // �ر��߳̾��
		KeWaitForSingleObject(&SystemBuffer.kEvent, Executive, KernelMode, TRUE, NULL);  // �ȴ��¼�
		״̬ = SystemBuffer.Status;
	} else {
		״̬ = ״̬_����_�����߳�ʧ��;
		KdPrint(("[%s] �����ں��߳�ʧ��. Status��%X", __FUNCTION__, Status));
	}
	// �ͷ�MDL
	MmUnmapLockedPages(Map, mdl);
	IoFreeMdl(mdl);
	// ��������
	RtlCopyMemory((PVOID)Buffer, &OutBuffer, 8);

	return ״̬;
}

NTSTATUS Memory::AllocMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size)
{
	NTSTATUS ״̬ = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	// �ж�Ŀ������Ƿ���Ч
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] Ŀ�������Ч.", __FUNCTION__));
		return ״̬_����_������Ч;
	}
	// �ж�Ŀ������Ƿ���ֹ
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] Ŀ������ѽ���.", __FUNCTION__));
		return ״̬_����_�����ѽ���;
	}
	
	ULONG64 OutBuffer = 0;
	typedef struct _ALLOC_MEMORY {
		PVOID Address;
		SIZE_T Size;
		PVOID OutBuffer;
	} ALLOC_MEMORY, *PALLOC_MEMORY;
	ALLOC_MEMORY pBuffer{ (PVOID)Address ,Size ,&OutBuffer };
	COPY_MEMORY SystemBuffer{ &pBuffer, sizeof(pBuffer), NULL, NULL };

	// ��ʼ���¼�
	KeInitializeEvent(&SystemBuffer.kEvent, SynchronizationEvent, FALSE);
	// ����ϵͳ�߳�
	HANDLE hThread = 0;
	Status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)SystemAllocMemory, &SystemBuffer);
	if (NT_SUCCESS(Status) && hThread)
	{
		KdPrint(("[%s] �����ں��̳߳ɹ�.", __FUNCTION__));
		ZwClose(hThread);  // �ر��߳̾��
		KeWaitForSingleObject(&SystemBuffer.kEvent, Executive, KernelMode, TRUE, NULL);  // �ȴ��¼�
		״̬ = SystemBuffer.Status;
	} else {
		״̬ = ״̬_����_�����߳�ʧ��;
		KdPrint(("[%s] �����ں��߳�ʧ��.Status��%X", __FUNCTION__, Status));
	}

	RtlCopyMemory(Buffer, &OutBuffer, 8);
	return ״̬;
}

NTSTATUS Memory::FreeMemory(ULONG64 Address, SIZE_T Size)
{
	NTSTATUS ״̬ = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	// �ж�Ŀ������Ƿ���Ч
	if (!ARGUMENT_PRESENT(TargetProcess) || !MmIsAddressValid(TargetProcess)) {
		KdPrint(("[%s] Ŀ�������Ч.", __FUNCTION__));
		return ״̬_����_������Ч;
	}
	// �ж�Ŀ������Ƿ���ֹ
	if (PsGetProcessExitStatus(TargetProcess) != STATUS_PENDING) {
		KdPrint(("[%s] Ŀ������ѽ���.", __FUNCTION__));
		return ״̬_����_�����ѽ���;
	}

	typedef struct _FREE_MEMORY {
		PVOID Address;
		SIZE_T Size;
	} FREE_MEMORY, *PFREE_MEMORY;
	FREE_MEMORY pBuffer{ (PVOID)Address ,Size };
	COPY_MEMORY SystemBuffer{ &pBuffer, sizeof(pBuffer), NULL, NULL };

	// ��ʼ���¼�
	KeInitializeEvent(&SystemBuffer.kEvent, SynchronizationEvent, FALSE);
	// ����ϵͳ�߳�
	HANDLE hThread = 0;
	Status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, (PKSTART_ROUTINE)SystemFreeMemory, &SystemBuffer);
	if (NT_SUCCESS(Status) && hThread)
	{
		KdPrint(("[%s] �����ں��̳߳ɹ�.", __FUNCTION__));
		ZwClose(hThread);  // �ر��߳̾��
		KeWaitForSingleObject(&SystemBuffer.kEvent, Executive, KernelMode, TRUE, NULL);  // �ȴ��¼�
		״̬ = SystemBuffer.Status;
	} else {
		״̬ = ״̬_����_�����߳�ʧ��;
		KdPrint(("[%s] �����ں��߳�ʧ��.Status��%X", __FUNCTION__, Status));
	}

	return ״̬;
}
