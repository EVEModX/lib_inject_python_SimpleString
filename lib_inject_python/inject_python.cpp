#include <stdio.h>
#include <Windows.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

extern "C"
{
	int RaisePrivileges(){
		int retCode = 0;
		HANDLE hToken;
		TOKEN_PRIVILEGES tp;
		TOKEN_PRIVILEGES oldtp;
		DWORD dwSize = sizeof(TOKEN_PRIVILEGES);
		LUID luid;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
			retCode = 1;
			goto error1;
		}
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)){
			retCode = 2;
			goto error2;
		}
		ZeroMemory(&tp, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwSize)){
			retCode = 3;
			goto error2;
		}
	error2:
		CloseHandle(hToken);
	error1:
		return retCode;
	}

	typedef struct{
		HMODULE(__stdcall *pGetModuleHandle)(LPCSTR);
		FARPROC(__stdcall *pGetProcAddress)(HMODULE, LPCSTR);
		char ModuleName[9];
		char PyGILState_Ensure[18];
		char PyRun_SimpleString[19];
		char PyGILState_Release[19];
		char *Code;
	} REMOTEDATA;

	static DWORD WINAPI ExecutePythonCode(REMOTEDATA *data)
	{
		DWORD retCode = 0;
		HMODULE hModule = data->pGetModuleHandle(data->ModuleName);
		if (hModule != NULL){
			int(__cdecl *a)() = reinterpret_cast<int(__cdecl *)()>(data->pGetProcAddress(hModule, data->PyGILState_Ensure));
			if (a != NULL){
				int ret = a();

				void(__cdecl *b)(char *) = reinterpret_cast<void(__cdecl *)(char *)>(data->pGetProcAddress(hModule, data->PyRun_SimpleString));
				if (b != NULL){
					b(data->Code);
				}
				else {
					retCode = 3;
				}

				void(__cdecl *c)(int) = reinterpret_cast<void(__cdecl *)(int)>(data->pGetProcAddress(hModule, data->PyGILState_Release));
				if (c != NULL){
					c(ret);
				}
				else {
					retCode = 4;
				}
			}
			else {
				retCode = 2;
			}
		}
		else {
			retCode = 1;
		}
		return retCode;
	}

	static void AfterExecutePythonCode(){
	}

	int InjectPythonCode(HANDLE hProcess, const char *code, char *moduleName){
		int retCode = 0;
		REMOTEDATA data;
		int cbCodeSize = (PBYTE)AfterExecutePythonCode - (PBYTE)ExecutePythonCode;
		void* remoteCodeString = VirtualAllocEx(hProcess, NULL, strlen(code) + 1, MEM_COMMIT, PAGE_READWRITE);
		if (remoteCodeString == NULL){
			retCode = 1;
			goto error1;
		}
		void* remoteCode = VirtualAllocEx(hProcess, NULL, cbCodeSize, MEM_COMMIT, PAGE_EXECUTE);
		if (remoteCode == NULL){
			retCode = 2;
			goto error2;
		}
		void* remoteData = VirtualAllocEx(hProcess, NULL, sizeof(data), MEM_COMMIT, PAGE_READWRITE);
		if (remoteData == NULL){
			retCode = 3;
			goto error3;
		}
		if (!WriteProcessMemory(hProcess, remoteCodeString, (void*)code, strlen(code) + 1, NULL)){
			retCode = 4;
			goto error3;
		}
		data.pGetModuleHandle = GetModuleHandleA;
		data.pGetProcAddress = GetProcAddress;
		strcpy_s(data.ModuleName, moduleName);
		strcpy_s(data.PyGILState_Ensure, "PyGILState_Ensure");
		strcpy_s(data.PyRun_SimpleString, "PyRun_SimpleString");
		strcpy_s(data.PyGILState_Release, "PyGILState_Release");
		data.Code = (char *)remoteCodeString;
		if (!WriteProcessMemory(hProcess, remoteData, (void*)&data, sizeof(data), NULL)){
			retCode = 5;
			goto error3;
		}
		if (!WriteProcessMemory(hProcess, remoteCode, (void*)ExecutePythonCode, cbCodeSize, NULL)){
			retCode = 6;
			goto error3;
		}
		HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCode, remoteData, 0, NULL);
		if (!hRemoteThread){
			retCode = 7;
			goto error3;
		}
		if (WaitForSingleObject(hRemoteThread, INFINITE) == WAIT_FAILED){
			retCode = 8;
			goto error4;
		}
		DWORD exitCode;
		if (!GetExitCodeThread(hRemoteThread, &exitCode)){
			retCode = 9;
			goto error4;
		}
		if (exitCode != 0){
			retCode = 10;
			goto error4;
		}
	error4:
		CloseHandle(hRemoteThread);
	error3:
		VirtualFreeEx(hProcess, remoteData, sizeof(data), MEM_RELEASE);
	error2:
		VirtualFreeEx(hProcess, remoteCode, cbCodeSize, MEM_RELEASE);
	error1:
		VirtualFreeEx(hProcess, remoteCodeString, strlen(code) + 1, MEM_RELEASE);
		return retCode;
	}

	int InjectPythonCodeToPID(DWORD pid, const char *code){
		char versions[][9] = { "Python34", "Python33", "Python32", "Python31", "Python30", "Python27", "Python26", "Python25", "Python24" };
		unsigned int numVersions = 9;
		unsigned int i;
		int retCode = 0;
		int ret;
		BOOL is32Bit;
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		if (!hProcess){
			retCode = 1;
			goto error1;
		}
		//TODO this requires windows xp an above, later check if the function exists first...
		if (!IsWow64Process(hProcess, &is32Bit)){
			retCode = 2;
			goto error2;
		}
#ifdef _WIN64
		if (is32Bit){
			retCode = 5;
			goto error2;
		}
#else
		BOOL amI32Bit;
		IsWow64Process(GetCurrentProcess(), &amI32Bit);
		if (amI32Bit && !is32Bit){
			retCode = 5;
			goto error2;
		}
#endif
		for (i = 0; i < numVersions; ++i){
			ret = InjectPythonCode(hProcess, code, versions[i]);
			if (ret == 0){
				break;
			}
			if (ret != 10){
				retCode = 3;
				goto error2;
			}
		}
		if (ret != 0){
			retCode = 4;
			goto error2;
		}
	error2:
		CloseHandle(hProcess);
	error1:
		return retCode;
	}

	BOOL APIENTRY DllMain(HMODULE hModule,
		DWORD  ul_reason_for_call,
		LPVOID lpReserved
		)
	{
		switch (ul_reason_for_call)
		{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
		}
		return TRUE;
	}
}
