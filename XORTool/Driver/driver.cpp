#include <wdm.h>       // Core WDM definitions
#include <ntddk.h>     // Driver-specific kernel-mode functions
#include <ntstatus.h>  // NTSTATUS definitions
#include <wdftypes.h>   // Windows Driver Framework types (if you're using WDF)
#include <stdlib.h>     // Standard C library functions (often less used in pure kernel-mode)
#include <cstdarg>
#include <stdio.h>
#include <cstdint>

//? or % without datatype
void DebugMessage(PCCH format, ...)
{
	CHAR message[512];
	va_list _valist;
	va_start(_valist, format);
	const ULONG N = _vsnprintf_s(message, sizeof(message) - 1, format, _valist);
	message[N] = L'\0';

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, message, _valist);

	va_end(_valist);
}

extern "C" __declspec(dllexport)
VOID
FunctionCode1()
{
	DebugMessage("MyDriver: FunctionCode1 called\n");
	DebugMessage("MyDriver: sad called\n");
	DebugMessage("MyDriver: FuncstionCode1 called\n");
	DebugMessage("MyDriver: sd called\n");
	DebugMessage("MyDriver: FunctasdionCode1 called\n");
	DebugMessage("MyDriver: Functi343434onCode1 called\n");
}

extern "C" __declspec(dllexport)
VOID
FunctionCode2()
{
	DebugMessage("MyDriver: FunctionCode2 called\n");
}

extern "C" __declspec(dllexport)
VOID FunctionCodeZ()
{
	__debugbreak();
}

static NTSTATUS XOR(void* function, uint64_t offset, uint64_t maxSize)
{
	int keyStart = offset % sizeof(RTL_OSVERSIONINFOW);

	if (!function || maxSize <= 0) {
		DebugMessage("Invalid function or size.\n");
		return STATUS_INVALID_PARAMETER;
	}

	//Completely arbitrary way of generating your key
	RTL_OSVERSIONINFOW versionInfo = { 0 };
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	NTSTATUS status = RtlGetVersion(&versionInfo);
	if (NT_SUCCESS(status)) {
		DebugMessage("Kernel Version: %d.%d.%d\n",
			versionInfo.dwMajorVersion,
			versionInfo.dwMinorVersion,
			versionInfo.dwBuildNumber);
	}
	else {
		DebugMessage("Error getting kernel version: 0x%X\n", status);
	}

	uint64_t currSize = 0;
	bool bFinish = false;

	BYTE byteCode[0x1000];

	BYTE key[sizeof(RTL_OSVERSIONINFOW)];
	memcpy_s(key, sizeof(key), &versionInfo, sizeof(RTL_OSVERSIONINFOW));
	

	//Array with all function address checking for overlaps could also work, having a specific function called stop at the end
	while (currSize < maxSize)
	{
		byteCode[currSize] = (*(BYTE*)((char*)function + currSize) ^ key[(keyStart + currSize) % sizeof(key)]);

		currSize++;
	}

	PMDL mdl = IoAllocateMdl(function, currSize, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		DebugMessage("IoAllocateMdl failed.\n");
		return STATUS_FAIL_CHECK;
	}

	PVOID mappedAddress = MmMapLockedPagesSpecifyCache(
		mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority
	);

	if (mappedAddress == NULL) {
		DebugMessage("MmMapLockedPagesSpecifyCache failed.\n");
		IoFreeMdl(mdl);
		return STATUS_FAIL_CHECK;
	}

	IoFreeMdl(mdl);


	NTSTATUS protectStatus = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
	if (NT_SUCCESS(protectStatus)) {
		__try {
			memcpy_s(function, currSize, byteCode, currSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DebugMessage("Exception during memory patching.\n");
		}
		// Revert the protection
		MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READ);
	}
	else {
		DebugMessage("MmProtectMdlSystemAddress failed: 0x%X\n", protectStatus);
	}

	MmUnmapLockedPages(mappedAddress, mdl);
	IoFreeMdl(mdl);
	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
	UNREFERENCED_PARAMETER(driverObject);
	UNREFERENCED_PARAMETER(regPath);

	DebugMessage("Driver loaded successfully.\n");

	XOR(FunctionCode1, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);
	FunctionCode1();
	XOR(FunctionCode1, 0, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1);

	XOR(FunctionCode2, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1, (uint64_t)FunctionCodeZ - (uint64_t)FunctionCode2);
	FunctionCode2();
	XOR(FunctionCode2, (uint64_t)FunctionCode2 - (uint64_t)FunctionCode1, (uint64_t)FunctionCodeZ - (uint64_t)FunctionCode2);

	return STATUS_SUCCESS;
}
