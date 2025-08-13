#pragma once

typedef struct _COPY_MEMORY
{
	PVOID Data;
	ULONG DataSize;
	NTSTATUS Status;
	KEVENT kEvent;  // µÈ´ýÊÂ¼þ
} COPY_MEMORY, * PCOPY_MEMORY;

static ULONG64 PteBaseAddress;
static PEPROCESS TargetProcess;
static ULONG64 ProcessCR3;

class Memory
{
public:
	static NTSTATUS SetTargetProcess(HANDLE Processid);
	static NTSTATUS ReadMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size);
	static NTSTATUS WriteMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size);
	static NTSTATUS GetModulebase(PVOID ModuleNameBuffer, PVOID Buffer);
	static NTSTATUS AllocMemory(ULONG64 Address, PVOID Buffer, SIZE_T Size);
	static NTSTATUS FreeMemory(ULONG64 Address, SIZE_T Size);
};