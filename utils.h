#pragma once

#include <vector>
#include <Windows.h>

std::vector<std::uint8_t> read_file(const std::string& filename);
void check_pe_file(const std::vector<std::uint8_t>& targetfile);
void get_first(const std::vector<std::uint8_t> targetfile);
class PEFile {
private:
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS nt_header;
public:
    PEFile(const std::vector<uint8_t>& data) {
        auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
        auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(data.data() + dos_header->e_lfanew);
    }

    IMAGE_DOS_HEADER get_dos_header() const;
    IMAGE_NT_HEADERS get_nt_header() const;
    DWORD get_entrypoint() const;
    int get_size_of_optional_header() const;
    int get_num_of_sections() const;
    std::vector<uint32_t> get_section_addresses() const;
    void get_first_section_name() const;
};