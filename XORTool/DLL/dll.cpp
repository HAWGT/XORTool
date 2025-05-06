#include <windows.h>
#include <ntstatus.h>
#include <fstream>
#include <vector>
#include <iostream>

extern "C" __declspec(dllexport)
void FunctionCode1()
{
	std::cout << "MyDLL: FunctionCode1 called\n" << std::endl;
    std::cout << "MyDLL: asdasd called\n" << std::endl;
    std::cout << "MyDLL: Funct123ionCode1 called\n" << std::endl;
    std::cout << "MyDLL: fhdhfhd called\n" << std::endl;
    std::cout << "MyDLL: 2131241254 called\n" << std::endl;
}

extern "C" __declspec(dllexport)
void FunctionCode2()
{
    std::cout << "MyDLL: FunctionCode2 called\n" << std::endl;
}

extern "C" __declspec(dllexport)
void FunctionCodeZ()
{
    __debugbreak();
}

typedef NTSTATUS(NTAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);

bool XOR(void* function, uint64_t offset, uint64_t maxSize)
{
	if (!function || maxSize <= 0) {
		std::cerr << "Invalid function or size.\n";
		return false;
	}

    // Load ntdll.dll
    HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
    if (hNtdll == nullptr) {
        std::cerr << "Failed to load ntdll.dll. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Get the address of RtlGetVersion
    pRtlGetVersion RtlGetVersionProc = (pRtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
    if (RtlGetVersionProc == nullptr) {
        std::cerr << "Failed to get the address of RtlGetVersion. Error: " << GetLastError() << std::endl;
        FreeLibrary(hNtdll);
        return 1;
    }

    // Call RtlGetVersion
    RTL_OSVERSIONINFOW versionInfo = { sizeof(RTL_OSVERSIONINFOW) };
    NTSTATUS status = RtlGetVersionProc(&versionInfo);

    if (status != STATUS_SUCCESS) { // NTSTATUS 0 usually indicates success
        std::cerr << "RtlGetVersion failed with status: 0x" << std::hex << status << std::endl;
    }

    BYTE key[sizeof(RTL_OSVERSIONINFOW)];
    memcpy_s(key, sizeof(key), &versionInfo, sizeof(RTL_OSVERSIONINFOW));

    // Free the library
    FreeLibrary(hNtdll);

	int keyStart = offset % sizeof(RTL_OSVERSIONINFOW);

	BYTE byteCode[sizeof(RTL_OSVERSIONINFOW)];
	int currSize = 0;
	while (currSize < maxSize)
	{
		byteCode[currSize] = (*(BYTE*)((char*)function + currSize) ^ key[(keyStart + currSize) % sizeof(key)]);
		currSize++;
	}
	DWORD oldProtect;
	VirtualProtect(function, currSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy_s(function, currSize, byteCode, currSize);
	VirtualProtect(function, currSize, oldProtect, &oldProtect);

	return true;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        auto CreateConsole = [](const char* name) {
            FILE* ConsoleIO;
            if (!AllocConsole())
                return;

            freopen_s(&ConsoleIO, "CONIN$", "r", stdin);
            freopen_s(&ConsoleIO, "CONOUT$", "w", stderr);
            freopen_s(&ConsoleIO, "CONOUT$", "w", stdout);

            SetConsoleTitleA(name);
            };
		CreateConsole("XORTool");
		std::cout << "MyDLL: DLL loaded\n" << std::endl;

		XOR(FunctionCode1, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);
        FunctionCode1();
		XOR(FunctionCode1, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);

		XOR(FunctionCode2, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);
		FunctionCode2();
		XOR(FunctionCode2, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

