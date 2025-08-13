#include "Main.h"

NTOS_VERSION __fastcall GetSystemInfo()
{
    RTL_OSVERSIONINFOW osInfo{};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);

    NTSTATUS Status = RtlGetVersion(&osInfo);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[%s] 无法获取系统版本信息.", __FUNCTION__));
        return NTOS_UNKNOWN;
    }

    if (osInfo.dwBuildNumber == 10240) return NTOS_WIN10_1507;
    if (osInfo.dwBuildNumber == 10586) return NTOS_WIN10_1511;
    if (osInfo.dwBuildNumber == 14393) return NTOS_WIN10_1607;
    if (osInfo.dwBuildNumber == 15063) return NTOS_WIN10_1703;
    if (osInfo.dwBuildNumber == 16299) return NTOS_WIN10_1709;
    if (osInfo.dwBuildNumber == 17134) return NTOS_WIN10_1803;
    if (osInfo.dwBuildNumber == 17763) return NTOS_WIN10_1809;
    if (osInfo.dwBuildNumber == 18362) return NTOS_WIN10_1903;
    if (osInfo.dwBuildNumber == 18363) return NTOS_WIN10_1909;
    if (osInfo.dwBuildNumber == 19041) return NTOS_WIN10_20H1;
    if (osInfo.dwBuildNumber == 19042) return NTOS_WIN10_20H2;
    if (osInfo.dwBuildNumber == 19043) return NTOS_WIN10_21H1;
    if (osInfo.dwBuildNumber == 19044) return NTOS_WIN10_21H2;
    if (osInfo.dwBuildNumber == 19045) return NTOS_WIN10_22H2;

    if (osInfo.dwBuildNumber == 20348) return NTOS_WINSERVER_2022;

    if (osInfo.dwBuildNumber == 22000) return NTOS_WIN11_21H2;
    if (osInfo.dwBuildNumber == 22621) return NTOS_WIN11_22H2;
    if (osInfo.dwBuildNumber == 22631) return NTOS_WIN11_23H2;
    if (osInfo.dwBuildNumber == 26100) return NTOS_WIN11_24H2;
    if (osInfo.dwBuildNumber == 26120) return NTOS_WIN11_24H2;
    if (osInfo.dwBuildNumber == 27842) return NTOS_WIN11_25H2A;
    if (osInfo.dwBuildNumber == 27881) return NTOS_WIN11_25H2B;

    KdPrint(("[%s] 当前系统版本未记录.", __FUNCTION__));
    return NTOS_UNKNOWN;
}