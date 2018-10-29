// launch.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "launch.h"

#define APP_NAME	"launch.exe"


void PrivilegeEscalation()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}

BOOL DoInjection(const char *pDllPath, HANDLE hProcess)
{
	DWORD injBufSize = lstrlen(pDllPath) + 1;
	LPVOID AllocAddr = VirtualAllocEx(hProcess, NULL, injBufSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, AllocAddr, (void*)pDllPath, injBufSize, NULL);
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	HANDLE hRemoteThread;
	if ((hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pfnStartAddr, AllocAddr, 0, NULL)) == NULL)
	{
		return FALSE;
	}
	WaitForSingleObject(hRemoteThread, INFINITE);
	CloseHandle(hRemoteThread);
	return TRUE;
}

int startup(char *app, char *cmdline, const char *dll)
{
	PrivilegeEscalation();

	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi = { 0 };
	BOOL bok = CreateProcess(app, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED,
		NULL, NULL, &si, &pi);
	if (bok != TRUE)
	{
		MessageBox(NULL, "Startup program failed. ", APP_NAME, MB_OK);
		return GetLastError();
	}
	bok = DoInjection(dll, pi.hProcess);
	if (bok != TRUE)
	{
		MessageBox(NULL, "Injection crack.dll failed. ", APP_NAME, MB_OK);
		return GetLastError();
	}
	ResumeThread(pi.hThread);
	return 0;
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	// lpCmdLine launch.exe test.vmp.exe cmdline
	if (__argc < 2)
	{
		MessageBox(NULL, "Command line argument error. Unspecified startup program. ", APP_NAME, MB_OK);
		return -2;
	}

	const char *dll = "crack.dll";

	char *app = __argv[1];
	if (app[0] == '-' && app[1] == 'n')
	{
		app = __argv[2];
		dll = "rsa-n.dll";
	}

	char *cmdline = 0;
	if (__argc > 2)
	{
		char *p1 = strstr(lpCmdLine, app);
		p1 += strlen(app);
		p1 = strchr(p1, ' ');
		if (p1 != 0)
			cmdline = p1 + 1;
	}

	return (int)startup(app, cmdline, dll);
}


