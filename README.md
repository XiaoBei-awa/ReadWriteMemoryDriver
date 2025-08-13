# ReadWriteMemoryDriver

功能介绍：<br/>
Hook NtOpenFile 与用户层通讯。<br/>
1.获取进程模块基址：挂靠进程后使用ZwQueryVirtualMemory查询模块信息。<br/>
2.读写内存：自映射物理内存到虚拟内存，无内存缺页，可强制读写内存，但效率低下。<br/>
3.申请内存：挂靠进程后使用ZwAllocateVirtualMemory申请内存。<br/>
4.释放内存：同理，使用ZwFreeVirtualMemory释放内存。<br/>
5.保护内存：Hook NtReadVirtualMemory 修改缓冲区为保护的值。<br/>
如果有帮助到你，可以把我添加到你的星标吗？<br/>
<br/>
Features Describes:<br/>
Hook NtOpenFile Communicate with the R3<br/>
1.GetProcessModuleBase: After Attach process,use ZwQueryVirtualMemory to query module information.<br/>
2.ReadWriteMemory: Manually mapping physical memory to virtual memory, no Page Fault, can force read and write memory, but is inefficient.<br/>
3.AllocateMemory: After Attach process,use ZwAllocateVirtualMemory function.<br/>
4.FreeMemory: Similarly，use ZwFreeVirtualMemory function.<br/>
5.LockMemory: Hook NtReadVirtualMemory Modify the buffer value to the previously locked value.<br/>
If it helps you, could you please add me to your stars?

InfinityHook from : https://github.com/zhutingxf/InfinityHookPro
