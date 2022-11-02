# PE_Virus

用于软件安全实验。

## 项目构成

- 基础病毒: 含不具传染性的 junior，和具有传染性的 advance。

- 后门病毒: 在 advance 的基础上，实现了在宿主机上执行远端命令，并返回执行结果的功能。

examples 中为实验过程中尝试和测试时编写的代码，与项目无关。

## 基础病毒

### 目录构成

以下的目录和文件，隶属于**基础病毒**部分。

D:.  
│  blank.exe.bak  
│  clear.bat  
│  project.bat  
│  
├─src  
│  │  
│  ├─shellcode  
│  │      advance.c  
│  │      advance2.c  
│  │      junior.c  
│  │      tiny.c  
│  │  
│  └─tools  
│          build_tools.bat  
│          dump.c  
│          format.c  
│          infect.c  
│          shellcode.c  
│          trans.c  
└─test  

### 文件功能

- blank.exe.bak: 简单的 32 位程序，会在控制台输出 "Hello World!"，测试中**被用作病毒的传染对象**。
- project.bat: 基础病毒部分的管理脚本，提供了**简单的交互和命令集成**。
- clear.bat: 删除项目中的所有 .bin .exe .obj 文件，会被 project.bat 调用。
- src/shellcode
  - tiny.c: 最简单的荷载代码，**无功能，无传染性，只有跳转回程序入口的语句**。
  - junior.c: **不具传染性**。可以**加载使用 kernel32 中的函数**。效果是检测同目录下的 txt 文件并复制一份。
  - advance.c: 真正的**病毒框架**，无特殊功能，但具有自我复制、传染的能力，不需要 infect.c 承载可自行运行。
  - advance2.c: 在 advance 的基础上添加了 junior 的功能。通过定义 CONFIG_BACKDOOR，可以在宿主机上创建一个后门程序。
- src/tools
  - build_tools.bat: 用于编译本目录下的程序，会被 project.bat 调用。
  - dump.c: **PE 节提取工具**。将 PE section 提取为 .bin 文件。
  - format.c: 一个简单的字符串辅助工具。将读入转化为字符数组的定义语句。编程时可使用。
  - trans.c: **二进制文件转化工具**。将 .bin 转化为字符数组定义，并输出到标准输出中。
  - shellcode.c: infect.c 所包含的荷载代码 (字符数组定义)。测试中一般用 trans 动态生成，此处只是示例。
  - infect.c: 将 shellcode 作为新节 .ex 插入到指定的 pe 文件中 (通过标准输入指定)。
- test
  - 用于测试的文件夹，project.bat 执行测试时会自动生成

### test junior 效果解释

核心语句 (出自 project.bat):

```bat
echo "Test string!" > %test%\copy_me.txt
(echo hello.exe) | .\infect.exe
.\hello.exe
dumpbin hello.exe
```

首先，执行 infect.exe，将荷载代码插入到 hello.exe 中。

然后，执行 hello.exe，它会执行荷载代码，将目录下的 copy_me.txt 复制到 2020302181032.txt 中。执行完荷载代码后，它会返回到原本的程序入口，正常打印 "Hello World!"。

同时，可以在 dumpbin 中观察到 hello.exe 中新加的节 .ex。

### test advance2 效果解释

核心语句 (出自 project.bat):

```bat
copy advance2.exe %test%\virus.exe
copy %root%\blank.exe.bak %test%\hello1.exe
cd %test%
.\virus.exe
copy %root%\blank.exe.bak %test%\hello2.exe
.\hello1.exe
echo "Test string!" > %test%\copy_me.txt
.\hello2.exe
dumpbin hello2.exe
```

首先，virus.exe 将病毒荷载代码传染给目录下所有未被传染的 exe 文件。

然后，hello1.exe 将病毒荷载代码传染给目录下所有未被传染的 .exe 并打印 "Hello World!"。

被传染的 hello2.exe 会执行 junior 的功能，并打印 "Hello World!"。

同时，可以在 dumpbin 中观察到 hello2.exe 中新加的节 .ex。

### 单独编译生成荷载代码的方法

以 junior.c 为例，使用下面的命令可以编译它:

```bat
cl /c /GS- /Ob1 junior.c
link /entry:ShellCode /subsystem:console junior.obj 
```

使用 dump.exe 可以将其荷载代码段提取为二进制文件:

```bat
dump.exe /f:junior.exe /s:.junior /ob:junior.bin
```

使用 trans.exe 可以将其转化为 C 语言字符数组定义（用于 infect.c）:

```bat
trans.exe junior.bin > shellcode.c
```

注意，trans.exe 识别跳转语句的方式是检查 0x11223344 的位置。

对于 advance 和 advance2，它本身就是具有传染功能的完整可执行代码，会自动获取和计算 shellcode。不需要使用 infect 承载，也就不需要 dump 和 trans。

### 手动编译获取传染源的方法

对于 junior 和 tiny，用上面的方法提取出 shellcode.c 后，与 infect.c 放置于同一目录下，编译:

```bat
cl /GS- infect.c
```

infect.exe 就是传染源。它会读入目标 PE 文件名，然后将 shellcode 传染给它。

对于 advance 和 advance2，直接编译链接后得到的就是传染源:

```bat
cl /c /GS- /Ob1 advance.c
link /entry:ShellCode /subsystem:console advance.obj
```

如果非要用 infect 承载 advance，需要自己观察跳转位置的偏移。使用下面的方法可以得到反汇编代码:

```bat
dumpbin /section:.advance /disasm advance.exe > advance.txt
```

## 后门病毒

### 功能介绍

在 advance2 的基础上，增加了一个后门函数 `Backdoor()`，这个函数通过 `CreateProcessA()` 调用 PowerShell，实现远端执行指令的功能。

在编译 `advance2.c` 时添加 `/DCONFIG_BACKDOOR` 定义 `CONFIG_BACKDOOR` 这个宏，即可启用后门功能。

同时，`src/server` 文件夹中还提供了一个服务端程序，可以用于发布待执行的指令，并接受执行结果。

### 编译并运行服务端 Docker

服务端使用 Python 编写，为了保证环境的一致性，我们提供了一个 Dockerfile。使用以下命令可以编译并运行服务端：

```bash
cd src/server
docker build -t virus-server:1 .
touch /path/to/log/result.txt
docker run -v /path/to/log/result.txt:/result.txt --name virus-server virus-server
```
需要注意的是，这里的 /path/to/log 需要改为存放执行结果的文件。

另外，由于服务端的地址是写在 `advance2.c` 里面的 PowerShell 脚本里的，如果想要使用自定义的服务器，需要修改脚本中的地址，并重新编译 `advance2.c`。