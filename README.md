# PE_Virus

用于软件安全实验。

编写一个PE文件传染程序infect.exe，功能要求如下：

1. infect.exe运行后，向同目录下的某个Windows可执行程序（下称目标程序，建议找一个免安装的绿色程序，以方便测试。），植入“病毒载荷”代码。
2. infect.exe不能重复传染目标程序。
3. 【初级任务】目标程序被植入“病毒载荷”后，具备如下行为：一旦执行，就会在其同目录下查找是否有.txt文件，如果有，则任选一个，将其内容复制到另一个位置，文件名为本组某个同学的学号。
4. 【进阶任务】在完成初级任务的情况下，增加如下病毒行为：在其同目录下查找是否有.exe文件，如果有，则传染之。
5. 初级任务和进阶任务，任选一项完成即可。如果选择的是进阶任务，且实现了预期功能，则本次实验成绩90分起评。

examples 是调用模块的示例。

待办:

- 动态获取所需函数
- 编写感染程序
- 结合上述两项，编写 shellcode

需要的函数有:

```c
// 由于获取文件夹下的所有文件
// FindFirstFileA
typedef HANDLE (WINAPI *__FindFirstFileA) (
    _In_ LPCSTR lpFileName,
    _Out_ LPWIN32_FIND_DATAA lpFindFileData
);
// FindClose
typedef BOOL (WINAPI *__FindClose) (
    _Inout_ HANDLE hFindFile
);
// FindNextFileA
typedef BOOL (WINAPI *__FindNextFileA) (
    _In_ HANDLE hFindFile,
    _Out_ LPWIN32_FIND_DATAA lpFindFileData
);

// 用于打开、修改 (传染) 文件
// CreateFileA
typedef HANDLE (WINAPI *__CreateFileA) (
    _In_ LPCSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile
);
// WriteFile
typedef BOOL (WINAPI *__WriteFile) (
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);
// ReadFile
typedef BOOL (WINAPI *__ReadFile) (
    _In_ HANDLE hFile,
    _Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToRead,
    _Out_opt_ LPDWORD lpNumberOfBytesRead,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);
// SetFilePointer
typedef DWORD (WINAPI *__SetFilePointer) (
    _In_ HANDLE hFile,
    _In_ LONG lDistanceToMove,
    _Inout_opt_ PLONG lpDistanceToMoveHigh,
    _In_ DWORD dwMoveMethod
);

// handleapi.h
BOOL CloseHandle(
  [in] HANDLE hObject
);
```

# 编译并运行监听端 Docker

```bash
cd src/server
docker build -t virus-server:1 .
docker run -v /path/to/log/result.txt:/result.txt --name virus-server virus-server
```