#include <windows.h>
#include <string>
#include <windows.h>
#include <string>
#include <intrin.h>
#include <string.h>
#include "hwid.h"
#include "xor.h"
#include "print.h"
#include <filesystem>
#include <iostream>

char	m_szHardwareId[33];
char	szRawHardwareId[512];

char Serial::GetSystemDriveLetter(void)
{
	char szSystemDir[MAX_PATH];

	if (!GetSystemDirectoryA(szSystemDir, sizeof(szSystemDir)))
		return '\0';

	//report_info("L: %c", szSystemDir[0]);

	return szSystemDir[0];
}



PCHAR Serial::GetCPUVendorId(char* pszCPUVendorId)
{
	int iCPUInfo[4];
	__cpuid(iCPUInfo, 0);
	*((int*)(pszCPUVendorId)) = iCPUInfo[1];
	*((int*)(pszCPUVendorId + 4)) = iCPUInfo[3];
	*((int*)(pszCPUVendorId + 8)) = iCPUInfo[2];

	return pszCPUVendorId;
}

PCHAR Serial::GetHwProfileGuid(char* pszHwProfileGuid)
{
	HW_PROFILE_INFOA HwProfileInfo;

	if (!GetCurrentHwProfileA(&HwProfileInfo))
		return NULL;

	strcpy_s(pszHwProfileGuid, 39, HwProfileInfo.szHwProfileGuid);

	return pszHwProfileGuid;
}







PCHAR Serial::GetHardwareId(std::string id)
{
	// check if hwid already generated

	if (m_szHardwareId[0] && (strlen(m_szHardwareId) == 32))
		return m_szHardwareId;






	char value[255];
	DWORD BufferSize = sizeof(value);
	LONG res = RegGetValueA(HKEY_LOCAL_MACHINE, "SYSTEM\\HardwareConfig", "LastConfig", RRF_RT_REG_SZ, NULL, value, &BufferSize);
	if (res == 0)
	{

	}
	else
	{
		std::cerr << "[ldr_c] HI pt. 1 failed! " << res << std::endl;
	}



	//	char szHwProfileGuid[40];
		//ZeroMemory(szHwProfileGuid, sizeof(szHwProfileGuid));

	//	if (!GetHwProfileGuid(szHwProfileGuid))
	//	{
	//		print::set_error("[ldr_c] HI pt. 2 failed!");
	//		return NULL;
	//	}



	char szCPUVendorId[13];
	ZeroMemory(szCPUVendorId, sizeof(szCPUVendorId));
	if (!GetCPUVendorId(szCPUVendorId))
	{
		print::set_error("[ldr_c] HI pt. 3 failed!");
		return NULL;
	}



	// part 4

	sprintf_s(szRawHardwareId, "%s@%s%s@", id.c_str(), value, szCPUVendorId);
	return szRawHardwareId;
}