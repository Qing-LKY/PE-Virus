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
        if (strcmp(DemandModuleBase + ppName[i], pcFuncName) == 0) {
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

__forceinline DWORD FindBase(PWCHAR DemandModuleName) {
    // Find ImageBase of kernel32.dll
    PEB* peb;
    __asm {
        mov eax, fs:[30h]   // fs points to teb
        mov peb, eax
    }
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

void ShellCode() {

    WCHAR DemandModuleName[] = {L'K', L'E', L'R', L'N', L'E', L'L',
        L'3', L'2', L'.', L'D', L'L', L'L'};
    CHAR s[] = {'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', '\0'};
    DWORD DemandModuleBase = FindBase(DemandModuleName);
    DWORD dwFuncVA = FindFunction(s, DemandModuleBase);
}

int main() {
    ShellCode();

    return 0;
}
