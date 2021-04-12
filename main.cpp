#include <iostream>
#include <windows.h>
#include <fstream>

using namespace std;

int main(int argc, const char* argv[]) {
//    ofstream output ("output.txt");
//    if(argc != 2) {
//        cout << "Usage: sectons.exe pe_file" << endl;
//        return 0;
//    }
    ifstream input;
    input.open("SpotifySetup.exe", ios::in | ios::binary); // TODO: change to argv[1]
    if(!input.is_open()) { // если вдруг его открыть не удалось, то выведем ошибку и выйдем
        cout << "Can't open file" << endl;
        return 0;
    }
    input.seekg(0, ios::end); //для этого переведем файловый указатель чтения в самый конец файла, получим его позицию
    streamoff filesize = input.tellg(); //это и будет размер файла в байтах
    input.seekg(0); //затем вернем файловый указатель в начало файла

    IMAGE_DOS_HEADER dos_header;
//    TODO: exclude check for specials methods
    input.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));
    if(input.bad() || input.eof()) { //если вдруг считать не удалось...
        cout << "Unable to read IMAGE_DOS_HEADER" << endl;
        return 0;
    }
    if(dos_header.e_magic != 'ZM') { //Первые два байта структуры должны быть MZ, но, так как в
        cout << "IMAGE_DOS_HEADER signature is incorrect" << endl; // x86 у нас обратный
        return 0; // порядок следования байтов, мы сравниваем эти байты со значением 'ZM'
    }
    if((dos_header.e_lfanew % sizeof(DWORD)) != 0) { // Начало заголовка самого PE-файла (IMAGE_NT_HEADERS) должно быть
        cout << "PE header is not DWORD-aligned" << endl; // выровнено на величину двойного слова (DWORD)
        return 0; // а иначе наш PE-файл некорректен
    }

    input.seekg(dos_header.e_lfanew); //Переходим на структуру IMAGE_NT_HEADERS и готовимся считать ее
    if(input.bad() || input.fail()) {
        cout << "Cannot reach IMAGE_NT_HEADERS" << endl;
        return 0;
    }


    IMAGE_NT_HEADERS nt_header; //читать будем IMAGE_NT_HEADERS только без дата директорий
    input.read(reinterpret_cast<char*>(&nt_header), sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
    if(input.bad() || input.eof()) {
        cout << "Error reading IMAGE_NT_HEADERS32" << endl;
        return 0;
    }
    if(nt_header.Signature != 'EP') { //Проверяем, что наш файл - PE сигнатура у него должна быть
        cout << "Incorrect PE signature" << endl; // "PE\0\0", EP из-за обратного порядок байтов
        return 0;
    }
    //позиция в файле таблицы секций - это размер всех заголовков полностью
    DWORD first_section = dos_header.e_lfanew + nt_header.FileHeader.SizeOfOptionalHeader
            + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);

    input.seekg(first_section); //переходим на первую секцию в таблице секций
    if(input.bad() || input.fail()) {
        std::cout << "Cannot reach section headers" << std::endl;
        return 0;
    }
    WORD number_of_sections = nt_header.FileHeader.NumberOfSections;

    // TODO: Write to file instead of console
    cout << "AddressOfEntryPoint: " << nt_header.OptionalHeader.AddressOfEntryPoint << endl; // адресе точки входа

    for (WORD i = 0; i < number_of_sections; i++) { // секциях
        IMAGE_SECTION_HEADER section_header;
        input.read(reinterpret_cast<char*>(&section_header), sizeof(IMAGE_SECTION_HEADER));
        cout << "Name: " << section_header.Name << endl;
        cout << "VirtualAddress: " << section_header.VirtualAddress << endl;
        cout << "Characteristics: " << section_header.Characteristics << endl;
        cout << "Misc.PhysicalAddress: " << section_header.Misc.PhysicalAddress << endl;
        cout << "Misc.VirtualSize: "<< section_header.Misc.VirtualSize << endl;
        cout << "NumberOfRelocations: "<< section_header.NumberOfRelocations << endl;
        cout << "PointerToLinenumbers: "<< section_header.PointerToLinenumbers << endl;
        cout << "PointerToRawData: "<< section_header.PointerToRawData << endl;
        cout << "PointerToRelocations: "<< section_header.PointerToRelocations << endl;
        cout << "SizeOfRawData: "<< section_header.SizeOfRawData << endl;
        cout << "--------------------" << endl;
    }
    return 0;
}
