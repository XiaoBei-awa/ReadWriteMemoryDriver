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
	KdPrint(("[%s] 成功删除文件.", __FUNCTION__));

	return result;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) 
{
	// 防止警告
	UNREFERENCED_PARAMETER(pRegistryPath);

	// 定义驱动卸载入口
	pDriverObject->DriverUnload = DriverUnLoad;

	// 初始化无限Hook
	if (KHook::Initialize(InfinityCallback))
	{
		KdPrint(("[%s] 无限Hook安装成功.", __FUNCTION__));
		InitializeMemoryProtection();
		if (KHook::Start())
		{
			KdPrint(("[%s] 无限Hook启用成功.", __FUNCTION__));
		} else KdPrint(("[%s] 无限Hook启用失败.", __FUNCTION__));
	} else KdPrint(("[%s] 无限Hook安装失败.", __FUNCTION__));

	Delete_File_Mode(((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->FullDllName.Buffer);

	return STATUS_SUCCESS;
}

VOID DriverUnLoad(PDRIVER_OBJECT pDriverObject)
{
	// 防止警告
	UNREFERENCED_PARAMETER(pDriverObject);

	// 卸载无限Hook
	if (KHook::Stop())
	{
		// 休眠1秒，确保系统的执行点已经不再当前驱动里面了
		LARGE_INTEGER integer{ 0 };
		integer.QuadPart = 10000 * -1000;
		KeDelayExecutionThread(KernelMode, FALSE, &integer);

		KdPrint(("[%s] 无限Hook卸载成功.", __FUNCTION__));
	} else KdPrint(("[%s] 无限Hook停止失败.", __FUNCTION__));

	CleanupMemoryProtection();
}