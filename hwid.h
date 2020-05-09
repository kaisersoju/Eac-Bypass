#pragma once

class Serial
{
private:

public:
	static  char GetSystemDriveLetter(void);
	static  DWORD get_system_physical_drive_index(void);
	static  PCHAR GetPhysicalDriveSN(char* pszSerialNumber, size_t uMaxLength);
	static  PCHAR GetHwProfileGuid(char* pszHwProfileGuid);
	static  PCHAR GetCPUVendorId(char* pszCPUVendorId);
	static  PCHAR GetHardwareId(std::string id);
	DWORD VolumeSerialNumber;
};
