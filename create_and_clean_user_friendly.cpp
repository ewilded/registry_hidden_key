// The first function (createHiddenRunKey()) started on the excerpt from https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf.
// This version allows to create and remove a NULL-byte prepended value \0\0EVILTEST to the HKCU\\hacky key (I created the key manually with regedit, to avoid messing with 
// the original SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run. Just want to test some Winapi/Native system call behaviors.
// Successfully compiled & run with Dev CPP on Win10 x64.

#include <windows.h>
#include <string.h>
#include <iostream>

#define HIDDEN_KEY_LENGTH 10


// Type definition for _UNICODE_STRING structure taken from https://docs.microsoft.com/en-us/windows/desktop/api/subauth/ns-subauth-_unicode_string
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// We want to use the native function call here (this version is just for educational/testing purpose), what we'll finally want to achieve
// is an unreadable registry key containing a nullbyte. We can achieve this by abusing the native API while creating the key instead of using the regular WIN API, 
// just like we do with other two operations (RegOpenKeyExW() and RegCloseKey()).
// we have to define the _NtSetValueKey() function like this, based on its native arguments and returned value (_NtSevValueKey is just the name for the type we choose here)
// so we can map the GetProcAddressA() result to a value of this type.
// Also, we want the function to remove this thing (since we can't do it with regedit, as the value is indisplayable to it - which is the whole point of this).
// Luckily, there is a corresponding function:
// https://www.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FKey%2FNtDeleteValueKey.html

typedef NTSTATUS (*_NtSetValueKey)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (*_NtDeleteValueKey)(HANDLE, PUNICODE_STRING);

void createHiddenKey(const WCHAR* runCmd)
{
	LSTATUS openRet = 0;
	NTSTATUS setRet = 0;
	HKEY hkResult = NULL;
	UNICODE_STRING ValueName = { 0 };

	// get the NtSetValueKey Native function address
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	_NtSetValueKey NtSetValueKey;
	NtSetValueKey=(_NtSetValueKey)GetProcAddress(hNtdll,"NtSetValueKey");
	

	wchar_t runkeyPath[0x100] = L"hacky";

	wchar_t runkeyPath_trick[0x100] = L"\0\0EVILTEST";  // uncomment for the 'hidden' value

	ValueName.Buffer = runkeyPath_trick;
	ValueName.Length = 2 * HIDDEN_KEY_LENGTH;
	ValueName.MaximumLength = 0;

	if (!(openRet = RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, 0, KEY_SET_VALUE, &hkResult)))
	{
		if (!(setRet = NtSetValueKey(hkResult, &ValueName, 0, REG_SZ, (PVOID)runCmd, wcslen(runCmd) * 2)))
		{
			printf("SUCCESS setting hidden run value!\n");
		}
		else
		{
			printf("FAILURE setting hidden run value! (setRet == 0x%X, GLE() == %d)\n", setRet, GetLastError());
		}
		RegCloseKey(hkResult);
	}
	else

	{
		printf("FAILURE opening RUN key in registry! (openRet == 0x%X, GLE() == %d)\n", openRet, GetLastError());
	}

}

void deleteHiddenKey()
{
	LSTATUS openRet = 0;
	NTSTATUS delRet = 0;
	HKEY hkResult = NULL;
	UNICODE_STRING ValueName = { 0 };

	// get the NtSetValueKey Native function address
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	_NtDeleteValueKey NtDeleteValueKey;
	NtDeleteValueKey=(_NtDeleteValueKey)GetProcAddress(hNtdll,"NtDeleteValueKey");
	

	wchar_t runkeyPath[0x100] = L"hacky";
	wchar_t runkeyPath_trick[0x100] = L"\0\0EVILTEST";  // uncomment for the 'hidden' value

	ValueName.Buffer = runkeyPath_trick;
	ValueName.Length = 2 * HIDDEN_KEY_LENGTH;
	ValueName.MaximumLength = 0;

	if (!(openRet = RegOpenKeyExW(HKEY_CURRENT_USER, runkeyPath, 0, KEY_ALL_ACCESS, &hkResult)))
	{
			// OK this won't work without using a Marshalling technique (to be able to call native system functions from managed code)
		if (!(delRet = NtDeleteValueKey(hkResult, &ValueName)))
		{
			printf("SUCCESS removing the fucking nullbyte key run value!\n");
		}
		else
		{
			printf("FAILURE removing the fucking nullbyte run value! (delRet == 0x%X, GetLastError() == %d)\n", delRet, GetLastError());
		}
		RegCloseKey(hkResult);
	}
	else
	{
		printf("FAILURE opening RUN key in registry! (openRet == 0x%X, GLE() == %d)\n", openRet, GetLastError());
	}
}

int main(int argc, char** argv) 
{
	if(argc!=2)
	{
		printf("Usage: %s create|delete\n",argv[0]);
		return 0;
	}
	if(strcmp(argv[1],"create")==0)
	{
		printf("Trying to create the HKCU\\hacky\\0\\0EVILTEST value...\n");
		wchar_t d[10] = L"TEST";
 		createHiddenKey(d);
	}
	else
	{
		printf("Trying to remove the HKCU\\hacky\\0\\0EVILTEST value...\n");
		deleteHiddenKey();
	}
	return 0;	
}
