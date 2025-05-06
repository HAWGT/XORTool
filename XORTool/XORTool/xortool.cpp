#include <iostream>
#include <windows.h>
#include <ntstatus.h>
#include <fstream>
#include <vector>
#include <filesystem>

// Define the function pointer type for RtlGetVersion
typedef NTSTATUS(NTAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);

int main() {
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

    BYTE key[sizeof(RTL_OSVERSIONINFOW)];
    memcpy_s(key, sizeof(key), &versionInfo, sizeof(RTL_OSVERSIONINFOW));

    if (status == STATUS_SUCCESS) { // NTSTATUS 0 usually indicates success
		std::wcout << L"Key Generated: ";

        for (int i = 0; i < sizeof(RTL_OSVERSIONINFOW); ++i)
            std::cout << key[i] << " ";
        std::cout << std::endl;
    }
    else {
        std::cerr << "RtlGetVersion failed with status: 0x" << std::hex << status << std::endl;
    }

    // Free the library
    FreeLibrary(hNtdll);

    std::string filename;

	std::cout << "Input file: ";

	std::cin >> filename;

	std::ifstream file(filename, std::ios::binary | std::ios::in);
    if (!file) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return 1;
    }

    // Use standard stream iterators.
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close(); // Close the input file after reading.

    if (buffer.empty()) {
        std::cerr << "Error: File is empty or could not be read." << std::endl;
        return 1;
    }
    std::cout << "Successfully read " << buffer.size() << " bytes from " << filename << " into the buffer." << std::endl;

    // Parse PE headers.
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS header signature." << std::endl;
        return 1;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid NT header signature." << std::endl;
        return 1;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = nullptr;
    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
    {
        DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        // Find the section that contains the export directory.
        PIMAGE_SECTION_HEADER sectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(buffer.data() + dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);
        PIMAGE_SECTION_HEADER exportSection = nullptr;
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            if (sectionHeaders[i].VirtualAddress <= exportDirRVA && exportDirRVA < sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize)
            {
                exportSection = &sectionHeaders[i];
                break;
            }
        }
        if (exportSection == nullptr)
        {
            std::cerr << "Could not find section containing export directory." << std::endl;
            return 1;
        }
        // Calculate the file offset of the export directory.
        DWORD exportDirFileOffset = exportSection->PointerToRawData + (exportDirRVA - exportSection->VirtualAddress);
        exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(buffer.data() + exportDirFileOffset);
    }
    else
    {
        std::cerr << "File does not contain any exports" << std::endl;
        return 1;
    }

    if (exportDirectory == nullptr) {
        std::cerr << "No export directory found." << std::endl;
        return 1;
    }

    DWORD addressOfFunctionsRVA = exportDirectory->AddressOfFunctions;
    DWORD addressOfNamesRVA = exportDirectory->AddressOfNames;
    DWORD addressOfNameOrdinalsRVA = exportDirectory->AddressOfNameOrdinals;
    DWORD numberOfNames = exportDirectory->NumberOfNames;

    std::cout << "Export Directory:" << std::endl;
    std::cout << "  AddressOfFunctions: 0x" << std::hex << std::setw(8) << std::setfill('0') << addressOfFunctionsRVA << std::dec << std::endl;
    std::cout << "  AddressOfNames:     0x" << std::hex << std::setw(8) << std::setfill('0') << addressOfNamesRVA << std::dec << std::endl;
    std::cout << "  AddressOfNameOrdinals: 0x" << std::hex << std::setw(8) << std::setfill('0') << addressOfNameOrdinalsRVA << std::dec << std::endl;
    std::cout << "  NumberOfNames:      " << numberOfNames << std::endl;

    // Get section headers.
    PIMAGE_SECTION_HEADER sectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(buffer.data() + dosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader);

    // Function to convert RVA to file offset.
    auto RVAtoFileOffset = [&](DWORD rva) -> DWORD {
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            if (sectionHeaders[i].VirtualAddress <= rva && rva < sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize) {
                return sectionHeaders[i].PointerToRawData + (rva - sectionHeaders[i].VirtualAddress);
            }
        }
        return 0; // Return 0 if not found.  Handle this in caller.
        };

    std::vector<DWORD> addressOfFunctions(numberOfNames);
    std::vector<DWORD> addressOfNames(numberOfNames);
    std::vector<WORD> addressOfNameOrdinals(numberOfNames);

    // Get file offsets.
    DWORD addressOfFunctionsOffset = RVAtoFileOffset(addressOfFunctionsRVA);
    DWORD addressOfNamesOffset = RVAtoFileOffset(addressOfNamesRVA);
    DWORD addressOfNameOrdinalsOffset = RVAtoFileOffset(addressOfNameOrdinalsRVA);

    if (addressOfFunctionsOffset == 0 || addressOfNamesOffset == 0 || addressOfNameOrdinalsOffset == 0)
    {
        std::cerr << "Error: Could not calculate file offset for export data." << std::endl;
        return 1;
    }
    // Read export data.
    memcpy_s(addressOfFunctions.data(), addressOfFunctions.size() * sizeof(DWORD), buffer.data() + addressOfFunctionsOffset, numberOfNames * sizeof(DWORD));
    memcpy_s(addressOfNames.data(), addressOfNames.size() * sizeof(DWORD), buffer.data() + addressOfNamesOffset, numberOfNames * sizeof(DWORD));
    memcpy_s(addressOfNameOrdinals.data(), addressOfNameOrdinals.size() * sizeof(WORD), buffer.data() + addressOfNameOrdinalsOffset, numberOfNames * sizeof(WORD));

    std::vector<DWORD> codeOffsets;
    std::cout << "Exported Functions:" << std::endl;
    for (DWORD i = 0; i < numberOfNames; ++i)
    {
        DWORD nameRVA = addressOfNames[i];
        DWORD nameOffset = RVAtoFileOffset(nameRVA);
        if (nameOffset == 0)
        {
            std::cerr << "Error: Could not calculate file offset for function name." << std::endl;
            return 1;
        }

        std::string functionName;
        const char* namePtr = reinterpret_cast<const char*>(buffer.data() + nameOffset);
        while (*namePtr != '\0')
        {
            functionName += *namePtr++;
        }

        DWORD functionRVA = addressOfFunctions[addressOfNameOrdinals[i]];
        DWORD functionCodeFileOffset = RVAtoFileOffset(functionRVA);

        if (functionName.rfind("FunctionCode", 0) == 0)
        {
            codeOffsets.push_back(functionCodeFileOffset);
        }
        std::cout << "  " << functionName << " (Offset: 0x" << std::hex << std::setw(8) << std::setfill('0') << functionCodeFileOffset << ")" << std::dec << std::endl;
    }

    // Patch the functions.
    uint64_t counter = 0;
    for (size_t i = 0; i < codeOffsets.size() - 1; ++i)
    {
        uint64_t offset = codeOffsets[i];
        uint64_t size = codeOffsets[i + 1] - codeOffsets[i];
        if (offset + size > buffer.size())
        {
            std::cerr << "Error: Patch size exceeds buffer bounds." << std::endl;
            return 1;
        }
        std::cout << "Patching function at offset: 0x" << std::hex << offset << ", size: " << size << std::dec << " bytes." << std::endl;
        for (uint64_t j = 0; j < size; ++j)
        {
            buffer[offset + j] ^= key[(counter + j) % sizeof(RTL_OSVERSIONINFOW)];
        }
        counter += size;
    }

    // Write the modified buffer to a new file.
    std::string outputFilename = "xor_" + filename;
    std::ofstream outFile(outputFilename, std::ios::binary);
    if (!outFile)
    {
        std::cerr << "Error creating output file: " << outputFilename << std::endl;
        return 1;
    }
    outFile.write(buffer.data(), buffer.size());
    outFile.close();

    std::cout << "Done! Output file: " << outputFilename << std::endl;
    return 0;
}