#include <windows.h>
#include <ntstatus.h>
#include <fstream>
#include <vector>
#include <iostream>

extern "C" __declspec(dllexport)
void FunctionCode1()
{
    std::cout << "MyConsole: FunctionCode1 called\n" << std::endl;
    std::cout << "MyConsole: asdasd called\n" << std::endl;
    std::cout << "MyConsole: Funct123ionCode1 called\n" << std::endl;
    std::cout << "MyConsole: fhdhfhd called\n" << std::endl;
    std::cout << "MyConsole: 2131241254 called\n" << std::endl;
}

extern "C" __declspec(dllexport)
void FunctionCode2()
{
    std::cout << "MyConsole: FunctionCode2 called\n" << std::endl;
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

int main()
{
    std::cout << "Hello World!\n";

    XOR(FunctionCode1, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);
    FunctionCode1();
    XOR(FunctionCode1, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);

    XOR(FunctionCode2, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);
    FunctionCode2();
    XOR(FunctionCode2, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);

    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
