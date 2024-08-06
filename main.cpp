#include <iostream>
#include <Windows.h>
#include <fstream>
#include <vector>
#include <string>
#include "utils.h"

int main(int argc, char** argv)
{
    

    std::cout << "[+] SMAT Started!\n";


    if (argc > 1) {
        std::cout << "[+] Starting to analyze file: " << argv[1] << std::endl;
    }
    else {
        std::cerr << "[-] No file provided to analyze.\n";
        ExitProcess(1);
    }

    std::ifstream fp(argv[1], std::ios::binary);

    if (!fp.is_open()) {
        std::cerr << "[-] Couldn't open file: " << argv[1] << std::endl;
        ExitProcess(2);
    }

    auto target_file = read_file(argv[1]);
    PEFile target_pe = PEFile(target_file);

    check_pe_file(target_file);

    target_pe.get_first_section_name();
    std::cout << "[+] File entrypoint: " << target_pe.get_entrypoint() << std::endl;

    auto nt_header = target_pe.get_nt_header();
    auto curr_section = IMAGE_FIRST_SECTION(nt_header);

    std::cout << "[+] Starting to print sections\n";
    int num_of_sections = target_pe.get_num_of_sections();
    for (int i = 0; i < num_of_sections; i++,curr_section++) {
        std::cout << "[+] Section Name: " << std::string((char*)curr_section->Name).substr(0, 8) <<
            " Raw Size: " << std::to_string(curr_section->SizeOfRawData) <<
            " Virtual Size: " << std::to_string(curr_section->Misc.VirtualSize) <<
            std::endl;
    }

    target_pe.print_import_table();
    return 0;

}
