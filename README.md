# NimGetSyscallStub

Get fresh Syscalls from a fresh ntdll.dll copy. This code can be used as an alternative to the already published awesome tools [NimlineWhispers](https://github.com/ajpc500/NimlineWhispers) and [NimlineWhispers2](https://github.com/ajpc500/NimlineWhispers2) by [@ajpc500](https://twitter.com/ajpc500).

The advantage of grabbing Syscalls dynamically is, that the signature of the Stubs is not included in the file and you don't have to worry about changing Windows versions.

To compile the shellcode execution template run the following:

```
nim c -d:release ShellcodeInject.nim
```

The result should look like this:

![alt text](https://github.com/S3cur3Th1sSh1t/NimGetSyscallStub/raw/main/PoC.PNG)

