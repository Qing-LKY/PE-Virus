# 调试笔记

## 1

成功的执行到了 ShellCodeMain。但是不确定找到的地址是否正确完好。

程序没能走出 ShellCodeMain。

## 2

程序没能走到 InfectTarget 前。

## 3

FindFirstFileA 顺利执行。

OpenTargetA 执行失败。

## 4

CreateFileA 指针为空。

## 5

在 FindAllFunc 里面，CreateFileA 的指针是正确的.

## 6

FindAllFunc 实际上正确的完成了它的使命。也就是说 CreateFileA 的指针是莫名奇妙的被修改了。

## 7

上面的问题还没有解决，但是发现 codeAdr 的地址没有这么简单，我们需要更复杂的计算。

## 8

修正了计算方式，修改了链接方式。

现在被感染程序也能执行 ShellCode 的功能了。但是它回不去。似乎是不太完整？
