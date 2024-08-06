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

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file