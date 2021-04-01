#include <iostream>
#include <windows.h>

int main() {

    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS nt_header;
    WORD number_of_sections = nt_header.FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER section_header[number_of_sections];

    for (WORD i = 0; i < number_of_sections; i++) {
        std::cout << section_header[i].Name << std::endl;
        std::cout << section_header[i].VirtualAddress << std::endl;
        std::cout << section_header[i].Characteristics << std::endl;
        std::cout << section_header[i].Misc.PhysicalAddress << std::endl;
        std::cout << section_header[i].Misc.VirtualSize << std::endl;
        std::cout << section_header[i].NumberOfLinenumbers << std::endl;
        std::cout << section_header[i].NumberOfRelocations << std::endl;
        std::cout << section_header[i].PointerToLinenumbers << std::endl;
        std::cout << section_header[i].PointerToRawData << std::endl;
        std::cout << section_header[i].PointerToRelocations << std::endl;
        std::cout << section_header[i].SizeOfRawData << std::endl;
    }

    std::cout << "working with PE files" << std::endl;
    return 0;
}
