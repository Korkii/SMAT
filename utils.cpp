#include <iostream>
#include <vector>
#include <cstdint>
#include <Windows.h>
#include "utils.h"
#include <fstream>


const IMAGE_DOS_HEADER* PEFile::get_dos_header() const {
    return this->dos_header;
}   

const IMAGE_NT_HEADERS* PEFile::get_nt_header() const {
    return this->nt_header;
}

DWORD PEFile::get_entrypoint() const {
    return get_nt_header()->OptionalHeader.AddressOfEntryPoint;
}

int PEFile::get_size_of_optional_header() const {
    return get_nt_header()->FileHeader.SizeOfOptionalHeader;
}

int PEFile::get_num_of_sections() const {
    return get_nt_header()->FileHeader.NumberOfSections;
}

DWORD PEFile::get_data_directory_RVA() const {
    return get_nt_header()->OptionalHeader.DataDirectory->VirtualAddress;
}

ULONGLONG PEFile::get_image_base() const {
    return get_nt_header()->OptionalHeader.ImageBase;
}

std::vector<uint32_t> PEFile::get_section_addresses() const {
    auto nt_header = get_nt_header();
    auto first_section = IMAGE_FIRST_SECTION(nt_header);

    int num_of_sections = get_num_of_sections();

    std::vector<uint32_t> section_addresses(num_of_sections);

    for (int i = 0; i < num_of_sections; ++i) {
        section_addresses[i] = (*first_section).PointerToRawData;
        first_section += 40;
    }

    return section_addresses;
}

void PEFile::get_first_section_name() const {


    // Parse the NT header
    auto nt_header = get_nt_header();
    auto first_section_header = IMAGE_FIRST_SECTION(nt_header);

    std::cout << "First section name: " << first_section_header->Name << std::endl;
}

void PEFile::print_import_table() const {
    
    auto nt_headers = get_nt_header();
    auto import_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto IMAGE_BASE = get_image_base();

    if (import_directory.Size == 0) {
        std::cout << "No import table found." << std::endl;
        return;
    }
    
    auto import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(IMAGE_BASE + import_directory.VirtualAddress);


    while (import_descriptor->Name) {
        auto dll_name = reinterpret_cast<const char*>(
            IMAGE_BASE + import_descriptor->Name);

        std::cout << "DLL: " << dll_name << std::endl;

        auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            IMAGE_BASE + import_descriptor->FirstThunk);

        while (thunk->u1.AddressOfData) {
            auto import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                IMAGE_BASE + thunk->u1.AddressOfData);

            std::cout << "  Function: " << import_by_name->Name << std::endl;
            ++thunk;
        }
        ++import_descriptor;
    }
}


void check_pe_file(const std::vector<std::uint8_t>& targetfile) {
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(targetfile.data());

    // IMAGE_DOS_SIGNATURE is 0x5A4D (for "MZ")
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "[-] target file image has no valid DOS header." << std::endl;
        ExitProcess(3);
    }

    auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(targetfile.data() + dos_header->e_lfanew);

    // IMAGE_NT_SIGNATURE is 0x4550 (for "PE")
    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "[-] target file image has no valid NT header." << std::endl;
        ExitProcess(4);
    }

    // IMAGE_NT_OPTIONAL_HDR64_MAGIC is 0x020B
    if (nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        std::cerr << "[-] only 64-bit executables are supported for this tool!" << std::endl;
        ExitProcess(5);
    }
}

std::vector<std::uint8_t> read_file(const std::string& filename) {
    std::ifstream fp(filename, std::ios::binary);

    if (!fp.is_open()) {
        std::cerr << "[-] couldn't open file: " << filename << std::endl;
        ExitProcess(2);
    }

    auto vec_data = std::vector<std::uint8_t>();
    vec_data.insert(vec_data.end(),
        std::istreambuf_iterator<char>(fp),
        std::istreambuf_iterator<char>());

    return vec_data;
}
