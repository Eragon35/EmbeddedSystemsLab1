#include <iostream>
#include <windows.h>
#include <fstream>
#include <vector>

using namespace std;

ifstream input;
IMAGE_DOS_HEADER dos_header;

bool checker() {
    if(!input.is_open()) { // если вдруг его открыть не удалось, то выведем ошибку и выйдем
        cout << "Can't open file" << endl;
        return true;
    }
    input.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
    if(input.bad() || input.eof()) { // если вдруг считать не удалось
        cout << "Unable to read IMAGE_DOS_HEADER" << endl;
        return true;
    }
    input.seekg(dos_header.e_lfanew); //Переходим на структуру IMAGE_NT_HEADERS и готовимся считать ее
    if(input.bad() || input.fail()) {
        cout << "Cannot reach IMAGE_NT_HEADERS" << endl;
        return true;
    }
    if(dos_header.e_magic != 'ZM') { // Первые два байта структуры должны быть MZ, но в
        cout << "IMAGE_DOS_HEADER signature is incorrect" << endl; // x86 обратный порядок
        return true; // следования байтов, мы сравниваем эти байты со значением 'ZM'
    }
    if((dos_header.e_lfanew % sizeof(DWORD)) != 0) { // Начало заголовка самого PE-файла (IMAGE_NT_HEADERS)
        cout << "PE header is not DWORD-aligned" << endl; // должно быть выровнено на величину DWORD
        return true; // иначе наш PE-файл некорректен
    }
    return false;
}

int main() {
    vector<IMAGE_SECTION_HEADER> vector;

    input.open("SpotifySetup.exe", ios::in | ios::binary);
    ofstream output ("output.txt");
    ofstream bin ("bin.txt");
    if (checker()) return 0;

    IMAGE_NT_HEADERS nt_header; // читать будем IMAGE_NT_HEADERS только без дата директорий
    input.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
    if(input.bad() || input.eof()) {
        cout << "Error reading IMAGE_NT_HEADERS32" << endl;
        return 0;
    }
    if(nt_header.Signature != 'EP') { // Проверяем, что наш файл - PE сигнатура
        cout << "Incorrect PE signature" << endl;
        return 0;
    }
    // позиция в файле таблицы секций - это размер всех заголовков полностью
    DWORD first_section = dos_header.e_lfanew + nt_header.FileHeader.SizeOfOptionalHeader
            + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);

    input.seekg(first_section); // переходим на первую секцию в таблице секций
    if(input.bad() || input.fail()) {
        std::cout << "Cannot reach section headers" << std::endl;
        return 0;
    }
    WORD number_of_sections = nt_header.FileHeader.NumberOfSections;

    output << "AddressOfEntryPoint: " << nt_header.OptionalHeader.AddressOfEntryPoint << endl; // адрес точки входа

    for (WORD i = 0; i < number_of_sections; i++) { // выводим информацию о секциях
        IMAGE_SECTION_HEADER section_header;
        input.read(reinterpret_cast<char*>(&section_header), sizeof(IMAGE_SECTION_HEADER));
        output << "Name: " << section_header.Name << endl;
        output << "VirtualAddress: 0x" << hex << section_header.VirtualAddress << endl;
        output << "Characteristics: 0x" << hex << section_header.Characteristics << endl;
        output << "Misc.PhysicalAddress: 0x" << hex << section_header.Misc.PhysicalAddress << endl;
        output << "Misc.VirtualSize: 0x" << hex << section_header.Misc.VirtualSize << endl;
        output << "NumberOfRelocations: 0x" << hex << section_header.NumberOfRelocations << endl;
        output << "PointerToLinenumbers: 0x" << hex << section_header.PointerToLinenumbers << endl;
        output << "PointerToRawData: 0x" << hex << section_header.PointerToRawData << endl;
        output << "PointerToRelocations: 0x" << hex << section_header.PointerToRelocations << endl;
        output << "SizeOfRawData: 0x" << hex << section_header.SizeOfRawData << endl;
        output << "--------------------" << endl;
        if (section_header.Characteristics & 0x20) vector.push_back(section_header);
    }

    for (IMAGE_SECTION_HEADER header : vector) {
        // TODO: write_binary_code
    }
    return 0;
}
