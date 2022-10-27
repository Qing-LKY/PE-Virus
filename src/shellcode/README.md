# Shell Code

## 病毒荷载代码

编译方式:

```sh
cl /c /Gs- shellcode.c
link -dll shellcode.obj
```

然后使用 PE_Bear 提取对应节的二进制数据，用 dump.exe 导出为 C 语言数组。

tiny.c: 获取 BaseImage，然后跳转回原本的 entry (跳转目的由感染程序控制)

## 二进制荷载代码转换工具

编译方式:

```sh
cl dump.c
```

直接运行: 输入二进制数据文件名，输出 C 语言代码。

带参数运行: 例如 `.\dump.exe shellcode.bin`，输出目标的 C 语言代码。
