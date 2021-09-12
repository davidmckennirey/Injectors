# Injectors

A collection of process injection techniques. None of these techniques are new research, this is simply for learning purposes.

## Credits

- [D/Invoke](https://github.com/TheWover/DInvoke) by TheWover, FuzzySec (b33f), and Cobbr
- Rasta Mouse for his [process injection blog post](https://rastamouse.me/exploring-process-injection-opsec-part-1/)

## Projects

### Encryptor

Python helper script to encrypt shellcode using AES or XOR. Output can be dropped directly into any process injection project.

### CreateRemoteThread

Classic process injection using P/Invoke.

1. OpenProcess (current process)
2. VirtualAllocEx
3. WriteProcessMemory
4. VirtualProtectEx (Change process memory from RW to RX)
5. CreateRemoteThread

### D-CreateRemoteThread

Classic process injection using syscalls courtesy of DynamicInvoke (D/Invoke).

1. NtOpenProcess (current process)
2. NtAllocateVirtualMemory
3. NtWriteVirtualMemory
4. NtProtectVirtualMemory
5. NtCreateThreadEx
