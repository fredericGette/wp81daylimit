#pragma once

#include <windows.h>

#define PROV_RSA_FULL           1
#define CRYPT_VERIFYCONTEXT     0xF0000000

typedef ULONG_PTR HCRYPTPROV;

extern "C" {
	WINBASEAPI HMODULE WINAPI LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
	WINBASEAPI HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName);
	WINBASEAPI DWORD WINAPI GetTickCount(VOID);
	WINADVAPI BOOL WINAPI CryptAcquireContextA(HCRYPTPROV *phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
	WINADVAPI BOOL WINAPI CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);
	WINADVAPI BOOL WINAPI CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
	WINBASEAPI HANDLE WINAPI GetStdHandle(DWORD nStdHandle);
	WINBASEAPI BOOL WINAPI GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode);
	WINBASEAPI BOOL WINAPI SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode);
	WINBASEAPI DWORD WINAPI WaitForMultipleObjects(DWORD nCount, HANDLE * lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
	WINBASEAPI DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
	WINBASEAPI HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
	WINBASEAPI HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
	WINBASEAPI VOID WINAPI Sleep(DWORD dwMilliseconds);
	WINBASEAPI HANDLE WINAPI FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
}

#define WIN32API_TOSTRING(x) #x

// Link exported function
#define WIN32API_INIT_PROC(Module, Name)  \
  Name(reinterpret_cast<decltype(&::Name)>( \
      ::GetProcAddress((Module), WIN32API_TOSTRING(Name))))

// Convenientmacro to declare function
#define WIN32API_DEFINE_PROC(Name) const decltype(&::Name) Name

class Win32Api {

private:
	// Returns a base address of KernelBase.dll
	static HMODULE GetKernelBase() {
		return GetBaseAddress(&::DisableThreadLibraryCalls);
	}

	// Returns a base address of the given address
	static HMODULE GetBaseAddress(const void *Address) {
		MEMORY_BASIC_INFORMATION mbi = {};
		if (!::VirtualQuery(Address, &mbi, sizeof(mbi))) {
			return nullptr;
		}
		const auto mz = *reinterpret_cast<WORD *>(mbi.AllocationBase);
		if (mz != IMAGE_DOS_SIGNATURE) {
			return nullptr;
		}
		return reinterpret_cast<HMODULE>(mbi.AllocationBase);
	}

public:
	const HMODULE m_Kernelbase;
	WIN32API_DEFINE_PROC(LoadLibraryExW);
	WIN32API_DEFINE_PROC(GetModuleHandleW);
	const HMODULE m_Kernel32legacy;
	WIN32API_DEFINE_PROC(WaitForMultipleObjects);
	const HMODULE m_CryptSp;
	WIN32API_DEFINE_PROC(CryptAcquireContextA);
	WIN32API_DEFINE_PROC(CryptGenRandom);
	WIN32API_DEFINE_PROC(CryptReleaseContext);

	Win32Api()
		: m_Kernelbase(GetKernelBase()),
		WIN32API_INIT_PROC(m_Kernelbase, LoadLibraryExW),
		WIN32API_INIT_PROC(m_Kernelbase, GetModuleHandleW),
		m_Kernel32legacy(GetModuleHandleW(L"KERNEL32LEGACY.DLL")),
		WIN32API_INIT_PROC(m_Kernel32legacy, WaitForMultipleObjects),
		m_CryptSp(LoadLibraryExW(L"CRYPTSP.dll", NULL, NULL)),
		WIN32API_INIT_PROC(m_CryptSp, CryptAcquireContextA),
		WIN32API_INIT_PROC(m_CryptSp, CryptGenRandom),
		WIN32API_INIT_PROC(m_CryptSp, CryptReleaseContext)

	{};

};