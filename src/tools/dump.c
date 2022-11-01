#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include <minwindef.h>
#include <fileapi.h>
#include <handleapi.h>

#include <stdio.h>
#include <malloc.h>
#include <string.h>

void disp_help() {
    printf("dump.exe: A PE section dump tool by Qing_LKY!\n");
    printf("Example: .\\dump.exe /f:pe.exe /s:.text /ob:out.bin\n");
    exit(0);
}

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

char *pe_name, *sec_name, *ob_name, *oc_name;

void parse_args(char *s) {
    int n = strlen(s);
    if(s[0] != '/') {
        printf("Unknown argment: %s", s);
        disp_help();
        exit(0);
    }
    if(s[1] == 'f' && s[2] == ':') {
        pe_name = s + 3;
        printf("PE File Name: %s\n", pe_name);
        return;
    }
    if(s[1] == 's' && s[2] == ':') {
        sec_name = s + 3;
        printf("Section Name: %s\n", sec_name);
        return;
    }
    if(s[1] == 'o' && s[2] == 'b' && s[3] == ':') {
        ob_name = s + 4;
        printf("Binary File: %s\n", ob_name);
        return;
    }
    if(s[1] == 'o' && s[2] == 'c' && s[3] == ':') {
        oc_name = s + 4;
        printf("C File of Bin: %s\n", oc_name);
        return;
    }
    printf("Unknown argment: %s", s);
    disp_help();
    exit(0);
}

void check_args() {
    if(pe_name == NULL) {
        puts("No pe files!");
        exit(1);
    }
    if(sec_name == NULL) {
        puts("No section names!");
        exit(1);
    }
    if(oc_name == NULL && ob_name == NULL) {
        puts("Needs out file name!");
        exit(1);
    }
}

HANDLE open_pe_file() {
    HANDLE hFile = CreateFileA(
        pe_name, 
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
IMAGE_SECTION_HEADER secHdr;

#define N (1 << 20)

char buf[N]; int siz;

void getSection(HANDLE hFile) {
    puts("Init Header Pointer...");
    PIMAGE_DOS_HEADER pDosHdr = &dosHdr;
    PIMAGE_FILE_HEADER pFileHdr = &fileHdr;
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = &optHdr;
    PIMAGE_SECTION_HEADER pSecHdr = &secHdr;
    puts("Get Dos Header...");
    // Get DOS Header
    ReadOffset(
        hFile, 0, FILE_BEGIN, 
        (PVOID)&dosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    puts("Check PE signature...");
    // Check Signature
    DWORD pe00;
    ReadOffset(
        hFile, pDosHdr->e_lfanew, FILE_BEGIN,
        (PVOID)&pe00, sizeof(DWORD)
    );
    puts("Get File Header...");
    // Get File Header
    ReadOffset(
        hFile, 0, FILE_CURRENT, 
        (PVOID)&fileHdr, sizeof(IMAGE_FILE_HEADER)
    );
    puts("Get Optional Header...");
    // Get Optional Header
    ReadOffset(
        hFile, 0, FILE_CURRENT, 
        (PVOID)&optHdr, 
        /* 224 when 32 bits, same as pFileHdr->SizeOfOptionalHeader */
        sizeof(IMAGE_OPTIONAL_HEADER32) 
    );
    puts("Check 32 bits...");
    if(pOptHdr->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        puts("Error: Not a 32 bits exe!");
        exit(1);
    }
    puts("Compare sections...");
    // Get Target Section Header
    long now_off = \
        pDosHdr->e_lfanew + 0x4 + sizeof(IMAGE_FILE_HEADER) + pFileHdr->SizeOfOptionalHeader;
    SetFilePointer(hFile, now_off, NULL, FILE_BEGIN);
    for(int i = 0; i < pFileHdr->NumberOfSections; i++) {
        ReadOffset(
            hFile, 0, FILE_CURRENT,
            pSecHdr, sizeof(IMAGE_SECTION_HEADER)
        );
        if(strcmp(sec_name, pSecHdr->Name) == 0) break;
    }
    puts("Gain target section...");
    // Get Target Section
    ReadOffset(
        hFile, pSecHdr->PointerToRawData, FILE_BEGIN,
        buf, pSecHdr->SizeOfRawData
    );
    siz = pSecHdr->SizeOfRawData;
    puts("Get section success!");
}

int main(int argc, char *argv[]) {
    if(argc == 1) {
        disp_help();
        return 0;
    }
    for(int i = 1; i < argc; i++) parse_args(argv[i]);
    check_args();
    HANDLE hFile = open_pe_file();
    getSection(hFile);
    if(ob_name != NULL) {
        puts("Write Binary...");
        FILE *fp = fopen(ob_name, "wb");
        fwrite(buf, 1, siz, fp);
        fclose(fp);
    }
    return 0;
}