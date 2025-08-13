#pragma once

void InitializeMemoryProtection();
void CleanupMemoryProtection();
NTSTATUS AddMemoryToProtectedList(HANDLE ProcessId, PVOID VirtualAddress, SIZE_T Size);

NTSTATUS MyNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);