# Shell Code

## 病毒荷载代码

编译方式:

```sh
cl /c /GS- /Ob1 shellcode.c
link -dll shellcode.obj
```

也可以编译为 exe:

```sh
cl /c /GS- /Ob1 shellcode.c
link /entry:ShellCode /subsystem:console shellcode.obj
```

然后使用 PE_Bear 提取对应节的二进制数据，用 dump.exe 导出为 C 语言数组。

## tiny

tiny.c: 获取 BaseImage，然后跳转回原本的 entry

无传染性。需要使用 infect.c 进行装载。

修改了 entry，新添了段，并回到原本的程序中。

```sh
# 编译为 DLL 文件
cl /c /GS- /Ob1 tiny.c
link -dll 
# 编译为
```

## junior

junior.c