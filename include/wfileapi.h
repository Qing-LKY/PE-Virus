// Our wrapper for windows fileapi.h
#include "typedef.h"

static inline int ReadOffset(SCSB *sb, HANDLE hFile, long offset, long mode, void* buf, long size) {
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

static inline int WriteOffset(SCSB *sb, HANDLE hFile, long offset, long mode, void* buf, long size) {
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
static inline int SetFileSize(SCSB *sb, HANDLE hFile, long size) {
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
