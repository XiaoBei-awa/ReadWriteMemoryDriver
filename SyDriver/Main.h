#pragma once
#include <ntifs.h>
#include <intrin.h>

#include "InfinityHook/hook.hpp"
#include "OSVersion.h"
#include "InfinityHook.h"
#include "mem.h"
#include "MemoryLock.h"
#include "struct.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
VOID DriverUnLoad(PDRIVER_OBJECT pDriverObject);