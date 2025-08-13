#include <iostream>
#include <chrono>
#include <Windows.h>
#include <tlhelp32.h>
#include "SyDriver/SyDriver.h"

// 通过进程名取进程ID
HWND ProcessNameGetProcessID(const wchar_t* ProcessName)
{
	PROCESSENTRY32 ProcessInfo{};
	HANDLE ProcessSnapshot = 0;
	BOOL Next = 0;
	ProcessSnapshot = CreateToolhelp32Snapshot(2, 0);
	if (ProcessSnapshot == 0) { return 0; }
	ProcessInfo.dwSize = sizeof(ProcessInfo);
	Next = Process32First(ProcessSnapshot, &ProcessInfo);
	while (Next)
	{
		if (wcscmp(ProcessInfo.szExeFile, ProcessName) == 0)
		{
			CloseHandle(ProcessSnapshot);
			return ((HWND)ProcessInfo.th32ProcessID);
		}
		else
		{
			Next = Process32Next(ProcessSnapshot, &ProcessInfo);
		}
	}
	CloseHandle(ProcessSnapshot);
	return(0);
}

void MyRead()
{
	HWND hwnd = FindWindowA("Progman", "Program Manager");
	HWND pid = 0;
	GetWindowThreadProcessId(hwnd, (LPDWORD)&pid);

	if (!SyDriver::SetTargetProcess(pid))
		printf("设置进程失败：%d\n", ERRORCODE);
	ULONG64 module = SyDriver::GetModuleBase(L"ntdll.dll");
	printf("ntdll.dll模块地址: %I64x\n", module);
	system("pause");
	DWORD64 Buffer = 0;
	if (!SyDriver::ReadMemory(module, &Buffer, 8))
		printf("读内存失败：%d\n", ERRORCODE);
	printf("读内存长整数: %I64d\n", Buffer);

	system("pause");
	SyDriver::AllocMemory(0, &Buffer,1024);
	printf("分配内存: %I64d\n", Buffer);

	system("pause");
	if (!SyDriver::LockMemoryR3(pid, Buffer,4))
		printf("锁定内存失败\n");
	printf("锁定内存: %I64d\n", Buffer);

	system("pause");
	DWORD a = 6666;
	if (!SyDriver::WriteMemory(Buffer, &a, 4))
		printf("写内存失败\n");
	printf("写入内存: %I64d\n", Buffer);

	system("pause");
	a = 0;
	if (!SyDriver::ReadMemory(Buffer, &a, 4))
		printf("读内存失败\n");
	printf("读出内存: %d\n", a);

	system("pause");
	if (!SyDriver::FreeMemory(Buffer, 0))
		printf("释放内存失败\n");
	printf("释放内存: %I64d\n", Buffer);
}

void MyRead2()
{
	HWND hwnd = FindWindowA("Progman", "Program Manager");
	HWND pid = 0;
	GetWindowThreadProcessId(hwnd, (LPDWORD)&pid);

	SyDriver::SetTargetProcess(pid);
	ULONG64 cmodule = SyDriver::GetModuleBase(L"ntdll.dll");
	printf("模块地址: %I64x\n", cmodule);
	ULONG64 Buffer = 0;
	if (SyDriver::ReadMemory(cmodule, &Buffer, 8))
	{
		printf("读内存整数: %I64d\n", Buffer);
	}
	system("pause");
	printf("开始百万次读测试\n");
	// 百万次读写测试
	using namespace std;
	using namespace std::chrono;
	const int iterations = 1000000;

	// 开始计时
	auto start = high_resolution_clock::now();
	bool success = true;

	for (int i = 0; i < iterations; ++i)
	{
		Buffer = 0;
		if (!SyDriver::ReadMemory(cmodule, &Buffer, 8))
		{
			success = false;
			if (ERRORCODE == 状态_错误_未映射物理内存)
			{
				break;
			}
		}
	}

	// 结束计时
	auto end = high_resolution_clock::now();

	// 计算耗时（毫秒）
	auto duration_ms = duration_cast<milliseconds>(end - start);

	if (!success)
	{
		cout << "读内存失败: " << ERRORCODE << endl;
	}

	// 输出结果
	cout << "百万次读共耗时:\n"
		<< duration_ms.count() << " ms\n";
}

void MyRead3()
{
	HWND hwnd = FindWindowA("Progman", "Program Manager");
	HWND pid = 0;
	GetWindowThreadProcessId(hwnd, (LPDWORD)&pid);

	SyDriver::SetTargetProcess(pid);
	ULONG64 cmodule = SyDriver::GetModuleBase(L"ntdll.dll");
	printf("模块地址: %I64x\n", cmodule);
	ULONG64 Buffer = 0;
	NTSTATUS status = SyDriver::ReadMemory(cmodule, &Buffer, 8);
	if (NT_SUCCESS(status))
	{
		printf("读内存整数: %I64d\n", Buffer);
	}
	system("pause");
	printf("开始刷多页读写测试\n");
	// 多页读写测试

	using namespace std;
	using namespace std::chrono;

	// 开始计时
	auto start = high_resolution_clock::now();

	LPVOID MemoryBuffer = VirtualAlloc(NULL, 0x1000000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // 1000页读写测试
	if (MemoryBuffer == 0) return;
	for (int i = 0; i < 1000; i++)
	{
		SyDriver::ReadMemory(cmodule + i * 0x1000, PVOID((ULONG64)MemoryBuffer + i * 0x1000), 0x1000);
	}
	printf("读出到: %p\n", MemoryBuffer);

	// 结束计时
	auto end = high_resolution_clock::now();

	// 计算耗时（毫秒）
	auto duration_ms = duration_cast<milliseconds>(end - start);

	// 输出结果
	cout << "1000页读写共耗时:\n"
		<< duration_ms.count() << " ms\n";

	system("pause");
	VirtualFree(MemoryBuffer, 0, MEM_RELEASE);
}

int main()
{
    if (SyDriver::CallTest()) std::cout << "与驱动通讯成功!\n";
	system("pause");
	MyRead();
	system("pause");

}
