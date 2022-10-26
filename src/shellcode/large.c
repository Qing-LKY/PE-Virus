#include <Windows.h>
#include <winternl.h>
#include <fileapi.h>
#include <stdio.h>

#pragma code_seg(".large")

#define DEBUG

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

__forceinline DWORD FindFunction(
        PCHAR pcFuncName,
        PIMAGE_EXPORT_NAME_POINTER pName,
        PIMAGE_EXPORT_ADDRESS_TABLE pAddr,
        PIMAGE_EXPORT_ORDINAL_TABLE pOrd,
        SIZE_T len
    ) {
    for (SIZE_T i = 0; i < len; i++) {
        if (strcmp(*pName, pcFuncName) == 0) {
            printf("%s\n", *pName);
            // Matched
            WORD ord = pOrd[i];
            return pAddr[ord].dwExportRVA;
        }
    }
    return 0;
}

void ShellCode() {

    // Find ImageBase of kernel32.dll
    PEB* peb;
    __asm {
        mov eax, fs:[30h]   // fs points to teb
        mov peb, eax
    }
    WCHAR DemandModuleName[] = {L'K', L'E', L'R', L'N', L'E', L'L',
        L'3', L'2', L'.', L'D', L'L', L'L'};
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
#ifdef DEBUG
                puts("Found kernel32.dll ImageBase");
#endif // DEBUG
                // found module
                DemandModuleBase = (DWORD)Module->DllBase;
            }
        }
        if (e == LdrDataListHead.Blink) break;
    }
    
    // Find address of EXPORT Directory Table
    PIMAGE_DOS_HEADER pDosHdr =  DemandModuleBase;
    PIMAGE_FILE_HEADER pFileHdr = (DemandModuleBase + pDosHdr->e_lfanew);
    PIMAGE_OPTIONAL_HEADER32 pOptHdr = pFileHdr + sizeof(IMAGE_FILE_HEADER);

    IMAGE_DATA_DIRECTORY ExportTableDirectory =
        pOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY d = DemandModuleBase + ExportTableDirectory.VirtualAddress;
    PIMAGE_EXPORT_ADDRESS_TABLE pAddr = DemandModuleBase + d->AddressOfFunctions;
    PIMAGE_EXPORT_NAME_POINTER pName = DemandModuleBase + d->AddressOfNames;
    PIMAGE_EXPORT_ORDINAL_TABLE pOrd = DemandModuleBase + d->AddressOfNameOrdinals;
    CHAR s[] = {'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e'};
    DWORD dwFuncVA = FindFunction(s, pName, pAddr, pOrd, d->NumberOfNames);
#ifdef DEBUG
    printf("%d\n", dwFuncVA);
#endif
}

int main() {
    ShellCode();

    return 0;
}
