#pragma warning(disable : 4201 4819 4311 4302)
#include "hook.hpp"
#include "utils.hpp"

namespace KHook
{
        InfinityCallbackPtr m_InfinityCallback = nullptr;
        unsigned long m_BuildNumber = 0;
        void* m_SystemCallTable = nullptr;
        bool m_DetectThreadStatus = true;
        void* m_EtwpDebuggerData = nullptr;
        void* m_CkclWmiLoggerContext = nullptr;
        void** m_EtwpDebuggerDataSilo = nullptr;
        void** m_GetCpuClock = nullptr;
        PETHREAD m_DetectThreadObject = NULL;
        PLONGLONG m_QpcPointer = NULL;
        PMDL m_QpcMdl = NULL;
        unsigned long long m_OriginalGetCpuClock = 0;
        unsigned long long m_HvlpReferenceTscPage = 0;
        unsigned long long m_HvlGetQpcBias = 0;
        unsigned long long m_HvlpGetReferenceTimeUsingTscPage = 0;
        unsigned long long m_HalpPerformanceCounter = 0;
        unsigned long long m_HalpOriginalPerformanceCounter = 0;
        unsigned long long m_HalpOriginalPerformanceCounterCopy = 0;
        unsigned long* m_HalpPerformanceCounterType = 0;
        unsigned char m_VmHalpPerformanceCounterType = 0;
        unsigned long m_OriginalHalpPerformanceCounterType = 0;
        unsigned long long m_OriginalHvlpGetReferenceTimeUsingTscPage = 0;
        typedef __int64 (*FHvlGetQpcBias)();
        FHvlGetQpcBias m_OriginalHvlGetQpcBias = nullptr;
        CLIENT_ID m_ClientId = { 0 };

        // �޸ĸ�������
        NTSTATUS EventTraceControl(ETWP_TRACE_TYPE nType)
        {
                const unsigned long nTag = 'VMON';

                // ����ṹ��ռ�
                CKCL_TRACE_PROPERTIES* pProperty = (CKCL_TRACE_PROPERTIES*)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, nTag);
                if (!pProperty)
                {
                        DbgPrintEx(0, 0, "[%s] allocate ckcl trace propertice struct fail \n", __FUNCTION__);
                        return STATUS_MEMORY_NOT_ALLOCATED;
                }

                // ���뱣�����ƵĿռ�
                wchar_t* szProviderName = (wchar_t*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 256 * sizeof(wchar_t), nTag);
                if (!szProviderName)
                {
                        DbgPrintEx(0, 0, "[%s] allocate provider name fail \n", __FUNCTION__);
                        ExFreePoolWithTag(pProperty, nTag);
                        return STATUS_MEMORY_NOT_ALLOCATED;
                }

                // ����ڴ�
                RtlZeroMemory(pProperty, PAGE_SIZE);
                RtlZeroMemory(szProviderName, 256 * sizeof(wchar_t));

                // ���Ƹ�ֵ
                RtlCopyMemory(szProviderName, L"Circular Kernel Context Logger", sizeof(L"Circular Kernel Context Logger"));
                RtlInitUnicodeString(&pProperty->ProviderName, (const wchar_t*)szProviderName);

                // Ψһ��ʶ��
                GUID guidCkclSession = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

                // �ṹ�����
                pProperty->Wnode.BufferSize = PAGE_SIZE;
                pProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                pProperty->Wnode.Guid = guidCkclSession;
                pProperty->Wnode.ClientContext = 3;
                pProperty->BufferSize = sizeof(unsigned long);
                pProperty->MinimumBuffers = 2;
                pProperty->MaximumBuffers = 2;
                pProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

                // ִ�в���
                unsigned long nLength = 0;
                if (nType == ETWP_TRACE_TYPE::EtwpUpdateTrace) pProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
                NTSTATUS ntStatus = NtTraceControl(nType, pProperty, PAGE_SIZE, pProperty, PAGE_SIZE, &nLength);

                // �ͷ��ڴ�ռ�
                ExFreePoolWithTag(szProviderName, nTag);
                ExFreePoolWithTag(pProperty, nTag);

                return ntStatus;
        }

        // ���ǵ��滻����,��Ե��Ǵ�Win7��Win10 1909��ϵͳ
        unsigned long long SelfGetCpuClock()
        {
                // �Ź��ں�ģʽ�ĵ���
                if (ExGetPreviousMode() == KernelMode) return __rdtsc();

                // �õ���ǰ�߳�
                PKTHREAD pCurrentThread = (PKTHREAD)__readgsqword(0x188);

                // ��ͬ�汾��ͬƫ��
                unsigned int nCallIndex = 0;
                if (m_BuildNumber <= 7601) nCallIndex = *(unsigned int*)((unsigned long long)pCurrentThread + 0x1f8);
                else nCallIndex = *(unsigned int*)((unsigned long long)pCurrentThread + 0x80);

                // �õ���ǰջ�׺�ջ��
                void** pStackMax = (void**)__readgsqword(0x1a8);
                void** pStackFrame = (void**)_AddressOfReturnAddress();

                // ��ʼ���ҵ�ǰջ�е�ssdt����
                for (void** pStackCurrent = pStackMax; pStackCurrent > pStackFrame; --pStackCurrent)
                {
                        /*     ���� PerfInfoLogSysCallEntry����
                                Win11 23606 ��ǰ ջ��ssdt��������, �ֱ���
                                mov r9d, 0F33h
                                mov [rsp+48h+var_20], 501802h
                                Win11 23606 ���Ժ� ջ��ssdt��������, �ֱ���
                                mov r9d, 0F33h
                                mov[rsp + 58h + var_30], 601802h
                        */
#define INFINITYHOOK_MAGIC_501802 ((unsigned long)0x501802) //Win11 23606 ��ǰϵͳ������
#define INFINITYHOOK_MAGIC_601802 ((unsigned long)0x601802) //Win11 23606 ���Ժ�ϵͳ��������
#define INFINITYHOOK_MAGIC_F33 ((unsigned short)0xF33)


                        // ��һ������ֵ���
                        unsigned long* pValue1 = (unsigned long*)pStackCurrent;
                        if ((*pValue1 != INFINITYHOOK_MAGIC_501802) &&
                                (*pValue1 != INFINITYHOOK_MAGIC_601802))
                        {
                                continue;
                        }

                        // ����Ϊʲô��?���Ѱ�ҵڶ�������ֵ��
                        --pStackCurrent;

                        // �ڶ�������ֵ���
                        unsigned short* pValue2 = (unsigned short*)pStackCurrent;
                        if (*pValue2 != INFINITYHOOK_MAGIC_F33)
                        {
                                continue;
                        }

                        // ����ֵƥ��ɹ�,�ٵ���������
                        for (; pStackCurrent < pStackMax; ++pStackCurrent)
                        {
                                // ����Ƿ���ssdt����
                                unsigned long long* pllValue = (unsigned long long*)pStackCurrent;
                                if (!(PAGE_ALIGN(*pllValue) >= m_SystemCallTable &&
                                        PAGE_ALIGN(*pllValue) < (void*)((unsigned long long)m_SystemCallTable + (PAGE_SIZE * 2))))
                                        continue;

                                // �����Ѿ�ȷ����ssdt����������
                                // �������ҵ�KiSystemServiceExit
                                void** pSystemCallFunction = &pStackCurrent[9];

                                // ���ûص�����
                                if (m_InfinityCallback) m_InfinityCallback(nCallIndex, pSystemCallFunction);

                                // ����ѭ��
                                break;
                        }

                        // ����ѭ��
                        break;
                }

                // ����ԭ����
                return __rdtsc();
        }

        // ���ǵ��滻����,��Ե���Win 1919���ϵ�ϵͳ
        EXTERN_C __int64 FakeHvlGetQpcBias()
        {
                // ���ǵĹ��˺���
                SelfGetCpuClock();

                // ����������HvlGetQpcBias��������
                 //������� HvlpReferenceTscPageָ��ֵΪ��
                if (*((unsigned long long*)m_HvlpReferenceTscPage) != 0)
                {
                        return *((unsigned long long*)(*((unsigned long long*)m_HvlpReferenceTscPage)) + 3);
                }
                return 0;
        }

        // �������
        void DetectThreadRoutine(void*)
        {
                while (m_DetectThreadStatus)
                {
                        // �̳߳�������
                        KUtils::Sleep(1000);
                        // GetCpuClock����һ������ָ��
                        if (m_BuildNumber <= 18363)
                        {

                                if (MmIsAddressValid(m_GetCpuClock) && MmIsAddressValid(*m_GetCpuClock))
                                {
                                        // ֵ��һ��,�������¹ҹ�
                                        if (SelfGetCpuClock != *m_GetCpuClock)
                                        {
                                                DbgPrintEx(0, 0, "[%s] fix 0x%p 0x%p \n", __FUNCTION__, m_GetCpuClock, MmIsAddressValid(m_GetCpuClock) ? *m_GetCpuClock : 0);
                                                if (Initialize(m_InfinityCallback)) Start();
                                        }
                                }
                                else Initialize(m_InfinityCallback); // GetCpuClock��Ч��Ҫ���»�ȡ
                        }
                        LARGE_INTEGER li = KeQueryPerformanceCounter(NULL);
                        //DbgPrintEx(0, 0, "[%s] Tick Count %lld \n", __FUNCTION__, li.QuadPart);
                }
                PsTerminateSystemThread(STATUS_SUCCESS);
        }
#define HALP_PERFORMANCE_COUNTER_TYPE_OFFSET (0xE4)  //HalpPerformanceCounter����ֵƫ�ƣ���ֵ�����������Ϊ5��������� Win11 22621 ����Ϊ7, ����Ϊ 8
#define HALP_PERFORMANCE_COUNTER_BASE_RATE_OFFSET (0xC0) //HalpPerformanceCounter�����ٶȱ��ʵ�ַ  �������ΪֵΪ 0x989680=10000000�� �������ΪԼ2000000000
#define HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE  (0x5) //�������HalpPerformanceCounter������
#define HALP_PERFORMANCE_COUNTER_BASE_RATE (10000000i64) //�����ٶ�


        bool Initialize(InfinityCallbackPtr pCallback)
        {
                if (!m_DetectThreadStatus) return false;

                // �ص�����ָ����
                DbgPrintEx(0, 0, "[%s] ssdt call back ptr is 0x%p \n", __FUNCTION__, pCallback);
                if (!MmIsAddressValid(pCallback)) return false;
                else m_InfinityCallback = pCallback;

                // �ȳ��Թҹ�
                if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace)))
                {
                        // �޷�����CKCL
                        if (!NT_SUCCESS(EventTraceControl(EtwpStartTrace)))
                        {
                                DbgPrintEx(0, 0, "[%s] start ckcl fail \n", __FUNCTION__);
                                return false;
                        }

                        // �ٴγ��Թҹ�
                        if (!NT_SUCCESS(EventTraceControl(EtwpUpdateTrace)))
                        {
                                DbgPrintEx(0, 0, "[%s] syscall ckcl fail \n", __FUNCTION__);
                                return false;
                        }
                }

                // ��ȡϵͳ�汾��
                m_BuildNumber = KUtils::GetSystemBuildNumber();
                DbgPrintEx(0, 0, "[%s] build number is %ld \n", __FUNCTION__, m_BuildNumber);
                if (!m_BuildNumber) return false;

                // ��ȡϵͳ��ַ
                unsigned long long ntoskrnl = KUtils::GetModuleAddress("ntoskrnl.exe", nullptr);
                DbgPrintEx(0, 0, "[%s] ntoskrnl address is 0x%llX \n", __FUNCTION__, ntoskrnl);
                if (!ntoskrnl) return false;

                // ���ﲻͬϵͳ��ͬλ��
                // https://github.com/FiYHer/InfinityHookPro/issues/17  win10 21h2.2130 ��װ KB5018410 ��������Ҫʹ���µ������� 
                unsigned long long EtwpDebuggerData = KUtils::FindPatternImage(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".text");
                if (!EtwpDebuggerData) EtwpDebuggerData = KUtils::FindPatternImage(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".data");
                if (!EtwpDebuggerData) EtwpDebuggerData = KUtils::FindPatternImage(ntoskrnl, "\x00\x00\x2c\x08\x04\x38\x0c", "??xxxxx", ".rdata");
                DbgPrintEx(0, 0, "[%s] etwp debugger data is 0x%llX \n", __FUNCTION__, EtwpDebuggerData);
                if (!EtwpDebuggerData) return false;
                m_EtwpDebuggerData = (void*)EtwpDebuggerData;

                // ������ʱ��֪����ô��λ,ƫ��0x10��ȫ��ϵͳ��һ��
                m_EtwpDebuggerDataSilo = *(void***)((unsigned long long)m_EtwpDebuggerData + 0x10);
                DbgPrintEx(0, 0, "[%s] etwp debugger data silo is 0x%p \n", __FUNCTION__, m_EtwpDebuggerDataSilo);
                if (!m_EtwpDebuggerDataSilo) return false;

                // ����Ҳ��֪����ô��λ,ƫ��0x2��ȫ��ϵͳ��Ŷһ��
                m_CkclWmiLoggerContext = m_EtwpDebuggerDataSilo[0x2];
                DbgPrintEx(0, 0, "[%s] ckcl wmi logger context is 0x%p \n", __FUNCTION__, m_CkclWmiLoggerContext);
                if (!m_CkclWmiLoggerContext) return false;

                /*  Win7ϵͳ����,m_GetCpuClock��ֵ��ı伸��,�Ƚ׶�ʹ���̼߳����޸�
                *   ��,Win11��ƫ�Ʊ����0x18,��©�ĺ��ҵ�����ô��  -_-
                *   �����ܽ�һ��,Win7��Win11����ƫ��0x18,��������0x28
                */
                if (m_BuildNumber <= 7601 || m_BuildNumber >= 22000) m_GetCpuClock = (void**)((unsigned long long)m_CkclWmiLoggerContext + 0x18); // Win7�汾�Լ�����, Win11Ҳ��
                else m_GetCpuClock = (void**)((unsigned long long)m_CkclWmiLoggerContext + 0x28); // Win8 -> Win10ȫϵͳ
                if (!MmIsAddressValid(m_GetCpuClock)) return false;
                DbgPrintEx(0, 0, "[%s] get cpu clock is 0x%p \n", __FUNCTION__, *m_GetCpuClock);

                // �õ�ssdtָ��
                m_SystemCallTable = PAGE_ALIGN(KUtils::GetSyscallEntry(ntoskrnl));
                DbgPrintEx(0, 0, "[%s] syscall table is 0x%p \n", __FUNCTION__, m_SystemCallTable);
                if (!m_SystemCallTable) return false;

                if (m_BuildNumber > 18363) // ���汾1909
                {
                        /* HvlGetQpcBias�����ڲ���Ҫ�õ�����ṹ
                        *   ���������ֶ���λ����ṹ
                        */
                        // ������Ϊ Win10 18363 �� Win11 22631ȫƽ̨ͨ��
                        unsigned long long addressHvlpReferenceTscPage = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\x40\x00\x48\x8b\x0d\x00\x00\x00\x00\x48\xf7\xe2",
                                "xxx????xxx?xxx????xxx");
                        if (!addressHvlpReferenceTscPage)
                        {
                                DbgPrintEx(0, 0, "[%s] Find HvlpReferenceTscPage Failed! \n", __FUNCTION__);
                                return false;
                        }
                        m_HvlpReferenceTscPage = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(addressHvlpReferenceTscPage) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(addressHvlpReferenceTscPage) + 3));
                        DbgPrintEx(0, 0, "[%s] HvlpReferenceTscPage is 0x%llX \n", __FUNCTION__, m_HvlpReferenceTscPage);
                        if (!m_HvlpReferenceTscPage) return false;
                        //-----------------------------------HvlpReferenceTscPage��ԭʼֵ----------------------------
                        //-----------------------------�����------------------�����-----------------------
                        //Win10  20H2                        ��                                  ��
                        //Win10  21H1                        ��                                  ��
                        //Win10  21H2                        ��                                  ��
                        //Win10  22H2                        ��                                  ��
                        //Win11  22000                       ��                                  ��
                        //Win11  22621                       ��                                  ��
                        //Win11  22631                       ��                                  ��
                        DbgPrintEx(0, 0, "[%s] HvlpReferenceTscPage Value Is 0x%llX \n", __FUNCTION__, *reinterpret_cast<unsigned long long*>(m_HvlpReferenceTscPage));
                        //if (*reinterpret_cast<unsigned long long*>(m_HvlpReferenceTscPage) == 0) return false; 

                        /* �������ǲ��ҵ�HvlGetQpcBias��ָ��
                        *   ��ϸ���ܿ��Կ�https://www.freebuf.com/articles/system/278857.html
                        */
                        //�ں��� HalpTimerQueryHostPerformanceCounter ��
                        //__int64 __fastcall HalpTimerQueryHostPerformanceCounter(_QWORD * a1)
                        //{
                        //        __int64 v2; // rbx

                        //        if (!HalpPerformanceCounter
                        //                || *(_DWORD*)(HalpPerformanceCounter + 0xE4) != 7
                        //                || !HvlGetQpcBiasPtr
                        //                || !HvlGetReferenceTimeUsingTscPagePtr)
                        //        {
                        //                return 0xC00000BB;
                        //        }
                        //        v2 = HvlGetReferenceTimeUsingTscPagePtr(0i64);
                        //        *a1 = HvlGetQpcBiasPtr() + v2;
                        //        return 0i64;
                        //}
                        unsigned long long addressHvlGetQpcBias = 0;
                        //HalpTimerQueryHostPerformanceCounter�в��� HvlGetQpcBias    ����� ����� HvlGetQpcBias ֵ��Ϊ0
                        addressHvlGetQpcBias = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x48\x83\x3d\x00\x00\x00\x00\x00\x74", // Win10 22H2��ǰ �Լ� Win11 22621��ǰ
                                "xxx????xxxx?xxx?????x");
                        if (!addressHvlGetQpcBias)
                        {
                                //��������ȫ���У����ϸ���������Win10 22H2 �Լ� Win11 22621����û�У����������ʱ���Ѿ��� Win10 22H2 �Լ� Win11 22621���ϰ汾
                                addressHvlGetQpcBias = KUtils::FindPatternImage(ntoskrnl,
                                        "\x48\x8b\x05\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x03\xd8\x48\x89\x1f",
                                        "xxx????x????xxxxxx");
                        }
                        if (!addressHvlGetQpcBias)
                        {
                                DbgPrintEx(0, 0, "[%s] Find HvlGetQpcBias Failed! \n", __FUNCTION__);
                                return false;
                        }
                        m_HvlGetQpcBias = reinterpret_cast<unsigned long long>(reinterpret_cast<char*>(addressHvlGetQpcBias) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(addressHvlGetQpcBias) + 3));
                        DbgPrintEx(0, 0, "[%s] HvlGetQpcBias Is 0x%llX \n", __FUNCTION__, m_HvlGetQpcBias);
                        if (!m_HvlGetQpcBias) return false;
                        //-----------------------------------HvlGetQpcBias��ԭʼֵ----------------------------
                        //-----------------------------�����------------------�����-----------------------
                        //Win10  20H2                        ��                                  ��
                        //Win10  21H1                        ��                                  ��
                        //Win10  21H2                        ��                                  ��
                        //Win10  22H2                        ��                                  ��
                        //Win11  22000                       ��                                  ��
                        //Win11  22621                       ��                                  ��             
                        //Win11  22631                       ��                                  ��
                        DbgPrintEx(0, 0, "[%s] HvlGetQpcBias Value Is 0x%llX \n", __FUNCTION__, *(unsigned long long*)m_HvlGetQpcBias);



                        //HalpTimerQueryHostPerformanceCounter�в��� HvlGetReferenceTimeUsingTscPagePtr 
                        //����� HvlGetReferenceTimeUsingTscPagePtr ֵΪ0
                        unsigned long long addressHvlpGetReferenceTimeUsingTscPage = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00\x33\xc9\xe8\x00\x00\x00\x00\x48\x8b\xd8",  //Win10 22H2 �� Win11 22621������
                                "xxx????xxxx?xxx????xxx");
                        if (!addressHvlpGetReferenceTimeUsingTscPage)
                        {
                                //��������ȫƽ̨���У����ϸ��������� Win10 22H2��ǰ�� �Լ� Win11 22621 ��ǰû�У����������ʱ���Ѿ��� Win10 21H1��21H2�� �Լ� Win11 22000�汾��
                                addressHvlpGetReferenceTimeUsingTscPage = KUtils::FindPatternImage(ntoskrnl,
                                        "\x48\x8b\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x03\xd8",
                                        "xxx????x????xxx");
                        }
                        if (!addressHvlpGetReferenceTimeUsingTscPage)
                        {
                                DbgPrintEx(0, 0, "[%s] Find HvlpGetReferenceTimeUsingTscPage Failed! \n", __FUNCTION__);
                                return false;
                        }
                        m_HvlpGetReferenceTimeUsingTscPage = (unsigned long long)
                                ((char*)(addressHvlpGetReferenceTimeUsingTscPage)+7 +
                                        *(int*)((char*)(addressHvlpGetReferenceTimeUsingTscPage)+3));
                        DbgPrintEx(0, 0, "[%s] HvlGetReferenceTimeUsingTscPage Is 0x%llX \n", __FUNCTION__, m_HvlpGetReferenceTimeUsingTscPage);
                        if (!m_HvlpGetReferenceTimeUsingTscPage) return false;
                        //-----------------------HvlpGetReferenceTimeUsingTscPage��ԭʼֵ----------------
                        //--------------------------------------�����---------------------------------------------------�����-----------------------
                        //Win10  20H2        nt!HvlGetReferenceTimeUsingTscPage                                                      ��
                        //Win10  21H1        nt!HvlGetReferenceTimeUsingTscPage                                                      ��
                        //Win10  21H2        nt!HvlGetReferenceTimeUsingTscPage                                                      ��
                        //Win10  22H2        nt!HvlGetReferenceTimeUsingTscPage                                                      ��
                        //Win11  22000       nt!HvlGetReferenceTimeUsingTscPage                                                      ��
                        //Win11  22621       nt!HvlGetReferenceTimeUsingTscPage                                                      ��                         
                        //Win11  22631       nt!HvlGetReferenceTimeUsingTscPage                                                      ��
                        DbgPrintEx(0, 0, "[%s] HvlGetReferenceTimeUsingTscPage Value Is 0x%llX \n", __FUNCTION__, *reinterpret_cast<unsigned long long*>(m_HvlpGetReferenceTimeUsingTscPage));


                        //HalpTimerQueryHostPerformanceCounter������HalpPerformanceCounter
                        unsigned long long  addressHalpPerformanceCounter = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x8b\xf9\x48\x85\xc0\x74\x00\x83\xb8", //������ȫƽ̨һ��
                                "xxx????xxxxxxx?xx");
                        if (!addressHalpPerformanceCounter)
                        {
                                DbgPrintEx(0, 0, "[%s] Find HalpPerformanceCounter Failed! \n", __FUNCTION__);
                                return false;
                        }
                        m_HalpPerformanceCounter = reinterpret_cast<unsigned long long>
                                (reinterpret_cast<char*>(addressHalpPerformanceCounter) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(addressHalpPerformanceCounter) + 3));
                        DbgPrintEx(0, 0, "[%s] HalpPerformanceCounter Is 0x%llX \n", __FUNCTION__, m_HalpPerformanceCounter);
                        if (!m_HalpPerformanceCounter) return false;
                        DbgPrintEx(0, 0, "[%s] HalpPerformanceCounter Value is 0x%llX \n", __FUNCTION__, *reinterpret_cast<unsigned long long*>(m_HalpPerformanceCounter));


                        //�� KiUpdateTime������HalpOriginalPerformanceCounter��Win10 21H1 �� Win11 22631 ͨ��
                        unsigned long long  addressHalpOriginalPerformanceCounter = KUtils::FindPatternImage(ntoskrnl,
                                "\x48\x8b\x05\x00\x00\x00\x00\x48\x3b\x00\x0f\x85\x00\x00\x00\x00\xA0",
                                "xxx????xx?xx????x");
                        if (!addressHalpOriginalPerformanceCounter)
                        {
                                //Win11 23606 ֮��,�� KeQueryPerformanceCounter ������HalpOriginalPerformanceCounter
                                addressHalpOriginalPerformanceCounter = KUtils::FindPatternImage(ntoskrnl,
                                        "\x48\x8b\x0d\x00\x00\x00\x00\x4c\x00\x00\x00\x00\x48\x3b\xf1",
                                        "xxx????x????xxx");
                                if (!addressHalpOriginalPerformanceCounter)
                                {
                                        DbgPrintEx(0, 0, "[%s] Find HalpOriginalPerformanceCounter Failed! \n", __FUNCTION__);
                                        return false;
                                }
                        }

                        m_HalpOriginalPerformanceCounter = reinterpret_cast<unsigned long long>
                                (reinterpret_cast<char*>(addressHalpOriginalPerformanceCounter) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(addressHalpOriginalPerformanceCounter) + 3));
                        DbgPrintEx(0, 0, "[%s] HalpOriginalPerformanceCounter Is 0x%llX \n", __FUNCTION__, m_HalpOriginalPerformanceCounter);
                        if (!m_HalpOriginalPerformanceCounter) return false;
                        DbgPrintEx(0, 0, "[%s] HalpOriginalPerformanceCounter Value Is 0x%llX \n", __FUNCTION__, *reinterpret_cast<unsigned long long*>(m_HalpOriginalPerformanceCounter));

                        //HalpPerformanceCounter�����͵�ָ�룬��������޸�ʱʹ��
                        m_HalpPerformanceCounterType = (ULONG*)((ULONG_PTR)(*(PVOID*)m_HalpPerformanceCounter) + HALP_PERFORMANCE_COUNTER_TYPE_OFFSET);
                        if (!m_HalpPerformanceCounterType)
                        {
                                DbgPrintEx(0, 0, "[%s] m_HalpPerformanceCounterType Is Null! \n", __FUNCTION__);
                                return false;
                        }
                        //�ж����������ʱ�Ž��к�ߵĲ���
                        if (*m_HalpPerformanceCounterType == HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE)
                        {
                                //����HalpTimerQueryHostPerformanceCounter���жϵ�Typeֵ����ʵҲ����ֱ���ж�ϵͳ�汾
                                //�ο�HalpTimerQueryHostPerformanceCounter�� *(_DWORD *)(HalpPerformanceCounter + 0xE4) != 7 ,
                                                                //Win11 22000 ������ֵΪ8  22621 ����Ϊ7
                                //����ǰ�������� addressHalpPerformanceCounter,����ע��ΪWin11 22621 HalpTimerQueryHostPerformanceCounter �� IDA�������
                                //.text : 0000000140520A1A 48 8B 05 8F 36 74 00                              mov     rax, cs : HalpPerformanceCounter
                                //.text : 0000000140520A21 48 8B F9                                                   mov     rdi, rcx
                                //.text : 0000000140520A24 48 85 C0                                                   test    rax, rax
                                //.text : 0000000140520A27 74 3F                                                         jz      short loc_140520A68
                                //.text : 0000000140520A29 83 B8 E4 00 00 00 07                                cmp     dword ptr[rax + 0E4h], 7
                                m_VmHalpPerformanceCounterType = *(reinterpret_cast<char*>(addressHalpPerformanceCounter) + 21);
                                DbgPrintEx(0, 0, "[%s] HalpPerformanceCounterType In Virtual Machine Value is 0x%x \n", __FUNCTION__, m_VmHalpPerformanceCounterType);

                                //����һ��ͬHalpPerformanceCounterһ���Ŀռ䣬�����滻HalpOriginalPerformanceCounter��
                                //�滻��������TypeΪ 5, ����Ϊ��׼�� 10000000, 
                                //ntoskrnl�е�ԭ�߼�Ϊ HalpOriginalPerformanceCounter = HalpPerformanceCounter
                                m_HalpOriginalPerformanceCounterCopy = (ULONGLONG)ExAllocatePool2(POOL_FLAG_NON_PAGED, 0xFF, 'freP');
                                if (!m_HalpOriginalPerformanceCounterCopy)
                                {
                                        DbgPrintEx(0, 0, "[%s] Allocate m_HalpOriginalPerformanceCounterReplace Failed!\n", __FUNCTION__);
                                        return false;
                                }
                                RtlZeroMemory((PVOID)m_HalpOriginalPerformanceCounterCopy, 0xFF);
                                //���û����ٶȣ�
                                *(PULONGLONG)(m_HalpOriginalPerformanceCounterCopy + HALP_PERFORMANCE_COUNTER_BASE_RATE_OFFSET) = HALP_PERFORMANCE_COUNTER_BASE_RATE;
                                *(PULONG)(m_HalpOriginalPerformanceCounterCopy + HALP_PERFORMANCE_COUNTER_TYPE_OFFSET) = HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE;
                                DbgPrintEx(0, 0, "[%s] m_HalpOriginalPerformanceCounterCopy��0x%llX \n", __FUNCTION__, m_HalpOriginalPerformanceCounterCopy);

                                // KUSER_SHARED_DATA��QpcBias�ֶΣ��ڴ�ϵͳ��˯��״̬�ָ�����״̬��ֹͣʱ��ϵͳʱ������ʱʹ��
                                PLONGLONG pQpcPointer = (PLONGLONG)0xFFFFF780000003B8;
                                m_QpcMdl = IoAllocateMdl(pQpcPointer, 8, false, false, NULL);
                                if (!m_QpcMdl)
                                {
                                        DbgPrintEx(0, 0, "[%s] m_QpcMdl IoAllocateMdl Failed!\n", __FUNCTION__);
                                        return false;
                                }
                                MmBuildMdlForNonPagedPool(m_QpcMdl);
                                m_QpcPointer = (PLONGLONG)MmMapLockedPagesSpecifyCache(m_QpcMdl, KernelMode, MmWriteCombined, NULL, false, NormalPagePriority);
                                if (!m_QpcPointer)
                                {
                                        DbgPrintEx(0, 0, "[%s] m_QpcPointer MmMapLockedPagesSpecifyCache Failed!\n", __FUNCTION__);
                                        return false;
                                }
                        }

                }

                return true;
        }

        ULONG64 FakeGetReferenceTimeUsingTscPage()
        {
                return __rdtsc();
        }

        bool Start()
        {
                if (!m_InfinityCallback) return false;

                // ��Чָ��
                if (!MmIsAddressValid(m_GetCpuClock))
                {
                        DbgPrintEx(0, 0, "[%s] get cpu clock vaild \n", __FUNCTION__);
                        return false;
                }

                /* ������������һ��ϵͳ�汾
                *   ��Win7��Win10 1909,m_GetCpuClock��һ������,����İ汾��һ����ֵ��
                *   ����3���쳣
                *   ����3��rdtsc
                *   ����2��off_140C00A30
                *   ����1��KeQueryPerformanceCounter
                *   ����0��RtlGetSystemTimePrecise
                *   ���ǵ������ο���ַhttps://www.freebuf.com/articles/system/278857.html
                *   ����������2����������
                */
                // ����GetCpuClockԭʼֵ,�˳�ʱ�ûָ�
                m_OriginalGetCpuClock = (unsigned long long)(*m_GetCpuClock);
                if (m_BuildNumber <= 18363)
                {
                        // ֱ���޸ĺ���ָ��
                        DbgPrintEx(0, 0, "[%s] GetCpuClock Is 0x%p\n", __FUNCTION__, *m_GetCpuClock);
                        *m_GetCpuClock = SelfGetCpuClock;
                        DbgPrintEx(0, 0, "[%s] Update GetCpuClock Is 0x%p\n", __FUNCTION__, *m_GetCpuClock);
                }
                else
                {

                        /* ������������Ϊ2, �����Ӳ��ܵ���off_140C00A30����
                        *   ��ʵ��ָ�����HalpTimerQueryHostPerformanceCounter����
                        *   �ú�������������������ָ��,��һ������HvlGetQpcBias,�������ǵ�Ŀ��
                        */
                        *m_GetCpuClock = (void*)2;
                        DbgPrintEx(0, 0, "[%s] Update GetCpuClock Is %p \n", __FUNCTION__, *m_GetCpuClock);

                        // �����HvlGetQpcBias��ַ,������������ʱ��ԭ����
                        m_OriginalHvlGetQpcBias = (HvlGetQpcBiasPtr)(*((unsigned long long*)m_HvlGetQpcBias));

                        //�����HvlpGetReferenceTimeUsingTscPageΪ�գ����������ָ��HvlGetReferenceTimeUsingTscPage������
                        //����ֵΪ��ʱ�����޸ģ�����ΪHvlGetReferenceTimeUsingTscPage�����������Ը�ΪNtYieldExecution��δ��������ZwYieldExecution�����������
                        //��ʵ���Ϊһ��û�в����ĺ���,�������� __rdtsc
                        if (m_HvlpGetReferenceTimeUsingTscPage)
                        {
                                //����ʹ��ԭ����HvlGetReferenceTimeUsingTscPage���� HvlpGetReferenceTimeUsingTscPage ֵΪ��ʱ��������������ݽṹδ��ʼ��
                                m_OriginalHvlpGetReferenceTimeUsingTscPage = *((unsigned long long*)m_HvlpGetReferenceTimeUsingTscPage);
                                if (m_OriginalHvlpGetReferenceTimeUsingTscPage == 0) //ֻ��HvlpGetReferenceTimeUsingTscPageֵΪ��ʱ�����ã���������ԭʼ����
                                {
                                        *((unsigned long long*)m_HvlpGetReferenceTimeUsingTscPage) = (ULONGLONG)FakeGetReferenceTimeUsingTscPage;
                                        DbgPrintEx(0, 0, "[%s] Update HvlpGetReferenceTimeUsingTscPage Value : %p \n", __FUNCTION__, (PVOID)FakeGetReferenceTimeUsingTscPage);
                                }

                        }


                        //��������ܼ����������� ���������Ϊ 7����8 �������Ϊ 5 �μ� HalpTimerSelectRoles �е� HalpTimerFindIdealPerformanceCounterSource
                        m_OriginalHalpPerformanceCounterType = *m_HalpPerformanceCounterType;
                        DbgPrintEx(0, 0, "[%s] Original HalpPerformanceCounterType Value : %d\n", __FUNCTION__, m_OriginalHalpPerformanceCounterType);
                        if (*m_HalpPerformanceCounterType == HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE) //ֻ�������������½����޸�
                        {
                                //���� HalpOriginalPerformanceCounter��ԭֵΪ m_HalpPerformanceCounter��ֵ 
                                *(unsigned long long*)m_HalpOriginalPerformanceCounter = m_HalpOriginalPerformanceCounterCopy;
                                DbgPrintEx(0, 0, "[%s] Update HalpOriginalPerformanceCounter Value: %llX\n", __FUNCTION__, m_HalpOriginalPerformanceCounterCopy);
                                LARGE_INTEGER li = KeQueryPerformanceCounter(NULL);
                                DbgPrintEx(0, 0, "[%s] Tick Count %lld \n", __FUNCTION__, li.QuadPart);
                                //��Ҫ�����ܼ��������͸�Ϊ����������µ��ж�ֵ�������߼� �μ� HalpTimerSelectRoles �е� HalpTimerFindIdealPerformanceCounterSource
                                *m_HalpPerformanceCounterType = m_VmHalpPerformanceCounterType;  //��Ϊ����������е����ͣ�7����8
                                DbgPrintEx(0, 0, "[%s] Update HalpPerformanceCounterType Value : %d\n", __FUNCTION__, m_VmHalpPerformanceCounterType);
                                li = KeQueryPerformanceCounter(NULL);
                                DbgPrintEx(0, 0, "[%s] Tick Count %lld \n", __FUNCTION__, li.QuadPart);
                        }


                        // ���ù���
                        *((unsigned long long*)m_HvlGetQpcBias) = (unsigned long long)FakeHvlGetQpcBias;
                        DbgPrintEx(0, 0, "[%s] Update HvlGetQpcBias Value is %p \n", __FUNCTION__, FakeHvlGetQpcBias);

                }

                static bool s_IsThreadCreated = false;
                if (!s_IsThreadCreated)
                {
                        s_IsThreadCreated = true;
                        OBJECT_ATTRIBUTES att{ 0 };
                        HANDLE hThread = NULL;
                        InitializeObjectAttributes(&att, 0, OBJ_KERNEL_HANDLE, 0, 0);
                        NTSTATUS ntStatus = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &att, 0, &m_ClientId, DetectThreadRoutine, 0);
                        if (!NT_SUCCESS(ntStatus))
                        {
                                DbgPrintEx(0, 0, "[%s] Create Detect Thread Failed! \n", __FUNCTION__);
                        }
                        else
                        {
                                ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&m_DetectThreadObject, NULL);
                                DbgPrintEx(0, 0, "[%s] Detect Routine Thread ID Is %d \n", __FUNCTION__, (int)m_ClientId.UniqueThread);
                                DbgPrintEx(0, 0, "[%s] Detect Routine Thread Object Is %p \n", __FUNCTION__, m_DetectThreadObject);
                        }

                }

                return true;
        }

        bool Stop()
        {
                // ֹͣ����߳�
                m_DetectThreadStatus = false;

                bool bResult = NT_SUCCESS(EventTraceControl(EtwpStopTrace)) && NT_SUCCESS(EventTraceControl(EtwpStartTrace));
                DbgPrintEx(0, 0, "[%s] Enter... \n", __FUNCTION__);

                if (m_DetectThreadObject)
                {
                        DbgPrintEx(0, 0, "[%s] Wait For Detect Thread Termination \n", __FUNCTION__);
                        KeWaitForSingleObject(m_DetectThreadObject, Executive, KernelMode, false, NULL);
                        //Win7 7600 ϵͳΪ ObDereferenceObject, Win7 7601������ΪObfDereferenceObject
                        //����MmGetSystemRoutineAddress��̬��ȡ��Ӧ�ĺ�����ַ�������Win7 7600�ϲ��ܼ�����������
                        UNICODE_STRING usObfDereferenceObject = RTL_CONSTANT_STRING(L"ObfDereferenceObject");
                        ObfDereferenceObjectPtr fnObfDereferenceObject = (ObfDereferenceObjectPtr)MmGetSystemRoutineAddress(&usObfDereferenceObject);
                        if (fnObfDereferenceObject)
                        {
                                fnObfDereferenceObject(m_DetectThreadObject);
                        }
                        else
                        {

                                UNICODE_STRING usObDereferenceObject = RTL_CONSTANT_STRING(L"ObDereferenceObject");
                                ObDereferenceObjectPtr fnObDereferenceObject = (ObDereferenceObjectPtr)MmGetSystemRoutineAddress(&usObDereferenceObject);
                                if (fnObDereferenceObject)
                                {
                                        fnObDereferenceObject(m_DetectThreadObject);
                                }
                                else
                                {
                                        DbgPrintEx(0, 0, "[%s] Can't Find ObDereferenceObject or ObfDereferenceObject \n", __FUNCTION__);
                                }
                        }
                        /*ObDereferenceObject(m_DetectThreadObject);*/
                        DbgPrintEx(0, 0, "[%s] Detect Thread Terminated \n", __FUNCTION__);
                }
                //m_GetCpuClockֵ��ԭҪ���߳�ֹ֮ͣ�󣬷�����ܻ�ԭ���ֱ��߳�����߼���Ϊ���ǵĺ�����
                *m_GetCpuClock = (void*)m_OriginalGetCpuClock;
                DbgPrintEx(0, 0, "[%s] Restore GetCpuClock is  %p \n", __FUNCTION__, *m_GetCpuClock);
                // Win10 1909����ϵͳ��Ҫ�ָ�����
                if (m_BuildNumber > 18363)
                {

                        if (m_HvlpGetReferenceTimeUsingTscPage)
                        {
                                //��ԭ HvlpGetReferenceTimeUsingTscPage��ֵΪm_OriginalHvlpGetReferenceTimeUsingTscPage��Ҳ�� 0
                                if (m_OriginalHvlpGetReferenceTimeUsingTscPage == 0)
                                {
                                        *((unsigned long long*)m_HvlpGetReferenceTimeUsingTscPage) = m_OriginalHvlpGetReferenceTimeUsingTscPage;
                                        DbgPrintEx(0, 0, "[%s] Restore HvlpGetReferenceTimeUsingTscPage Value is  0x%llX \n", __FUNCTION__, m_OriginalHvlpGetReferenceTimeUsingTscPage);
                                }
                        }

                        //ֻ��������Ͻ������»�ԭ
                        if (m_OriginalHalpPerformanceCounterType == HALP_PERFORMANCE_COUNTER_TYPE_PHYSICAL_MACHINE)
                        {
                                LARGE_INTEGER liBegin = KeQueryPerformanceCounter(NULL);
                                DbgPrintEx(0, 0, "[%s] Tick Count Before Restore %lld \n", __FUNCTION__, liBegin.QuadPart);
                                //��ԭ ˳�򱣳������˳��
                                *m_HalpPerformanceCounterType = m_OriginalHalpPerformanceCounterType;
                                //���ܻ�ԭm_HalpOriginalPerformanceCounterΪԭʼ��ֵ m_HalpPerformanceCounter, 
                                //����Ҫ����m_HalpOriginalPerformanceCounterΪm_HalpOriginalPerformanceCounterCopy��ֵ
                                //����ԭ�������ʱ�䷵�ػ��֮ǰС�ܶർ������
                                //*(unsigned long long*)m_HalpOriginalPerformanceCounter = m_HalpPerformanceCounter;

                                LARGE_INTEGER liEndFix = KeQueryPerformanceCounter(NULL);
                                //����˯��֮��ָ�����ֹͣʱʱ�������ϵͳ��������
                                if (liEndFix.QuadPart - liBegin.QuadPart > HALP_PERFORMANCE_COUNTER_BASE_RATE)
                                {
                                        LONGLONG llQpcValue = *m_QpcPointer;
                                        llQpcValue -= liEndFix.QuadPart - liBegin.QuadPart;
                                        *m_QpcPointer = llQpcValue;
                                        DbgPrintEx(0, 0, "[%s] Fix Qpc Value :%llX\n", __FUNCTION__, llQpcValue);
                                }

                                LARGE_INTEGER liEnd = KeQueryPerformanceCounter(NULL);
                                DbgPrintEx(0, 0, "[%s] Restore HalpPerformanceCounterType Value is  %ld \n", __FUNCTION__, m_OriginalHalpPerformanceCounterType);
                                DbgPrintEx(0, 0, "[%s] Tick Count After Restore %lld \n", __FUNCTION__, liEnd.QuadPart);
                                if (m_QpcMdl)
                                {
                                        DbgPrintEx(0, 0, "[%s] Free Qpc Mdl\n", __FUNCTION__);
                                        IoFreeMdl(m_QpcMdl);
                                        m_QpcMdl = NULL;
                                }
                        }
                        *((unsigned long long*)m_HvlGetQpcBias) = (unsigned long long)m_OriginalHvlGetQpcBias;
                        DbgPrintEx(0, 0, "[%s] Restore HvlGetQpcBias is %p \n", __FUNCTION__, m_OriginalHvlGetQpcBias);

                }

                if (bResult)
                {
                        DbgPrintEx(0, 0, "[%s] Stop Finished! \n", __FUNCTION__);
                }
                else
                {
                        DbgPrintEx(0, 0, "[%s] Stop Failed! \n", __FUNCTION__);
                }
                return bResult;
        }
}
