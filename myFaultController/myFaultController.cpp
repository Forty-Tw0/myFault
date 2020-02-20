#include "Windows.h"
#include "TlHelp32.h"
#include <iostream>
using namespace std;

DWORD GetModuleHandleByName(wchar_t* ModuleName, DWORD ProcID)
{
	MODULEENTRY32 ENTRY;
	ENTRY.dwSize = sizeof(MODULEENTRY32);
	HANDLE HSNAP = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcID);
	if (Module32First(HSNAP, &ENTRY) == TRUE)
	{
		if (!_wcsicmp(ENTRY.szModule, ModuleName))
		{
			DWORD HMODULE = (DWORD)ENTRY.modBaseAddr;
			return HMODULE;
		}
		else
		{
			while (Module32Next(HSNAP, &ENTRY) == TRUE)
			{
				if (!_wcsicmp(ENTRY.szModule, ModuleName))
				{
					DWORD HMODULE = (DWORD)ENTRY.modBaseAddr;
					return HMODULE;
				}
			}
			return 0;
		}
	}
	else
	{
		CloseHandle(HSNAP);
		return{ 0 };
	}
}

//get process handle
//NOTICE: THIS FUNCTION USES TCHAR, IF _UNICODE IS UNDEFINED, IT WILL NOT WORK. MAKE SURE YOUR APPLICATION IS SET TO USE UNICODE.
HANDLE GetProcessHandleByName(wchar_t* ProcessName)
{
	PROCESSENTRY32 ENTRY;
	ENTRY.dwSize = sizeof(PROCESSENTRY32);
	HANDLE HSNAP = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(HSNAP, &ENTRY) == TRUE)
	{
		if (!_wcsicmp(ENTRY.szExeFile, ProcessName))
		{
			HANDLE HPROC = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ENTRY.th32ProcessID);
			return HPROC;
		}
		else
		{
			while (Process32Next(HSNAP, &ENTRY) == TRUE)
			{
				if (!_wcsicmp(ENTRY.szExeFile, ProcessName))
				{
					HANDLE HPROC = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ENTRY.th32ProcessID);
					return HPROC;
				}
			}
			return 0;
		}
	}
	else
	{
		CloseHandle(HSNAP);
		return{ 0 };
	}
}

int main(){
	HANDLE dev = CreateFile(L"\\\\.\\myFault", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_DEVICE, NULL);

	UINT64 pid;
	cin >> pid;

	cout << GetModuleHandleByName(L"myFaultTest.exe", pid) << endl;

	LPVOID systemBuffer = &pid;
	LPVOID OutputBuffer = NULL;
	LPDWORD bytesReturned = 0;
	DeviceIoControl(dev, CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF42, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA), systemBuffer, sizeof(systemBuffer), OutputBuffer, sizeof(OutputBuffer), bytesReturned, NULL);
	
	CloseHandle(dev);
	system("pause");
}