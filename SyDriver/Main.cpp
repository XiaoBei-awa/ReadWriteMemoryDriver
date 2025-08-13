#include "Main.h"

NTSTATUS Delete_File_Mode(wchar_t* path)
{
	HANDLE fileHandle;
	NTSTATUS result;
	IO_STATUS_BLOCK ioBlock;
	void* object = NULL;
	OBJECT_ATTRIBUTES fileObject{};
	UNICODE_STRING uPath;

	PEPROCESS eproc = IoGetCurrentProcess();
	//switch context to UserMode

	KAPC_STATE pKs{};
	KeStackAttachProcess(eproc, &pKs);
	RtlInitUnicodeString(&uPath, path);

	InitializeObjectAttributes(&fileObject, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	result = IoCreateFileSpecifyDeviceObjectHint(&fileHandle, SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA, &fileObject, &ioBlock, 0, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0, CreateFileTypeNone, 0, IO_IGNORE_SHARE_ACCESS_CHECK, NULL);

	if (result != STATUS_SUCCESS)
	{
		KdPrint(("[%s] Error in IoCreateFileSpecifyDeviceObjectHint.", __FUNCTION__));
	}
	else {
		result = ObReferenceObjectByHandle(fileHandle, 0, 0, 0, &object, 0);

		if (result != STATUS_SUCCESS)
		{
			KdPrint(("[%s] error in ObReferenceObjectByHandle.", __FUNCTION__));
			ZwClose(fileHandle);
		}
		else
		{   /*METHOD 1*/
			((FILE_OBJECT*)object)->SectionObjectPointer->ImageSectionObject = 0;
			((FILE_OBJECT*)object)->DeleteAccess = 1;
			result = ZwDeleteFile(&fileObject);

			ObDereferenceObject(object);
			ZwClose(fileHandle);

			if (result != STATUS_SUCCESS)
			{
				KdPrint(("[%s] error in ZwDeleteFile.", __FUNCTION__));
			}
			else {
				result = ZwDeleteFile(&fileObject);
			}
		}
	}
	KeUnstackDetachProcess(&pKs);
	KdPrint(("[%s] �ɹ�ɾ���ļ�.", __FUNCTION__));

	return result;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) 
{
	// ��ֹ����
	UNREFERENCED_PARAMETER(pRegistryPath);

	// ��������ж�����
	pDriverObject->DriverUnload = DriverUnLoad;

	// ��ʼ������Hook
	if (KHook::Initialize(InfinityCallback))
	{
		KdPrint(("[%s] ����Hook��װ�ɹ�.", __FUNCTION__));
		InitializeMemoryProtection();
		if (KHook::Start())
		{
			KdPrint(("[%s] ����Hook���óɹ�.", __FUNCTION__));
		} else KdPrint(("[%s] ����Hook����ʧ��.", __FUNCTION__));
	} else KdPrint(("[%s] ����Hook��װʧ��.", __FUNCTION__));

	Delete_File_Mode(((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->FullDllName.Buffer);

	return STATUS_SUCCESS;
}

VOID DriverUnLoad(PDRIVER_OBJECT pDriverObject)
{
	// ��ֹ����
	UNREFERENCED_PARAMETER(pDriverObject);

	// ж������Hook
	if (KHook::Stop())
	{
		// ����1�룬ȷ��ϵͳ��ִ�е��Ѿ����ٵ�ǰ����������
		LARGE_INTEGER integer{ 0 };
		integer.QuadPart = 10000 * -1000;
		KeDelayExecutionThread(KernelMode, FALSE, &integer);

		KdPrint(("[%s] ����Hookж�سɹ�.", __FUNCTION__));
	} else KdPrint(("[%s] ����Hookֹͣʧ��.", __FUNCTION__));

	CleanupMemoryProtection();
}