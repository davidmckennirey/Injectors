{.passC:"-masm=intel".}

# NtOpenProcess -> NkuBbnmLpIlRkgSj
# NtAllocateVirtualMemory -> qUdzTJdDEkgLEmow
# NtWriteVirtualMemory -> osiboiBWRpRofhcq
# NtProtectVirtualMemory -> YxZNuSxVfOyuVhxK
# NtCreateThreadEx -> WWWkScycNMaiamzb

# Structs that weren't defined by winim
# These were pulled from syscalls.h
type
  PS_ATTR_UNION* {.pure, union.} = object
    Value*: ULONG
    ValuePtr*: PVOID
  PS_ATTRIBUTE* {.pure.} = object
    Attribute*: ULONG 
    Size*: SIZE_T
    u1*: PS_ATTR_UNION
    ReturnLength*: PSIZE_T
  PPS_ATTRIBUTE* = ptr PS_ATTRIBUTE
  PS_ATTRIBUTE_LIST* {.pure.} = object
    TotalLength*: SIZE_T
    Attributes*: array[2, PS_ATTRIBUTE]
  PPS_ATTRIBUTE_LIST* = ptr PS_ATTRIBUTE_LIST

proc qUdzTJdDEkgLEmow*(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                             
qUdzTJdDEkgLEmow_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  qUdzTJdDEkgLEmow_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  qUdzTJdDEkgLEmow_Check_10_0_XXXX
	jmp qUdzTJdDEkgLEmow_SystemCall_Unknown
qUdzTJdDEkgLEmow_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  qUdzTJdDEkgLEmow_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  qUdzTJdDEkgLEmow_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  qUdzTJdDEkgLEmow_SystemCall_6_3_XXXX
	jmp qUdzTJdDEkgLEmow_SystemCall_Unknown
qUdzTJdDEkgLEmow_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  qUdzTJdDEkgLEmow_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  qUdzTJdDEkgLEmow_SystemCall_6_1_7601
	jmp qUdzTJdDEkgLEmow_SystemCall_Unknown
qUdzTJdDEkgLEmow_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_19042
	cmp word ptr [rax+0x120], 19043
	je  qUdzTJdDEkgLEmow_SystemCall_10_0_19043
	jmp qUdzTJdDEkgLEmow_SystemCall_Unknown
qUdzTJdDEkgLEmow_SystemCall_6_1_7600:          
	mov eax, 0x0015
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_6_1_7601:          
	mov eax, 0x0015
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_6_2_XXXX:          
	mov eax, 0x0016
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_6_3_XXXX:          
	mov eax, 0x0017
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_10240:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_10586:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_14393:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_15063:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_16299:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_17134:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_17763:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_18362:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_18363:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_19041:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_19042:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_10_0_19043:        
	mov eax, 0x0018
	jmp qUdzTJdDEkgLEmow_Epilogue
qUdzTJdDEkgLEmow_SystemCall_Unknown:           
	ret
qUdzTJdDEkgLEmow_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc WWWkScycNMaiamzb*(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                      
WWWkScycNMaiamzb_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  WWWkScycNMaiamzb_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  WWWkScycNMaiamzb_Check_10_0_XXXX
	jmp WWWkScycNMaiamzb_SystemCall_Unknown
WWWkScycNMaiamzb_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  WWWkScycNMaiamzb_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  WWWkScycNMaiamzb_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  WWWkScycNMaiamzb_SystemCall_6_3_XXXX
	jmp WWWkScycNMaiamzb_SystemCall_Unknown
WWWkScycNMaiamzb_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  WWWkScycNMaiamzb_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  WWWkScycNMaiamzb_SystemCall_6_1_7601
	jmp WWWkScycNMaiamzb_SystemCall_Unknown
WWWkScycNMaiamzb_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  WWWkScycNMaiamzb_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  WWWkScycNMaiamzb_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  WWWkScycNMaiamzb_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  WWWkScycNMaiamzb_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  WWWkScycNMaiamzb_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  WWWkScycNMaiamzb_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  WWWkScycNMaiamzb_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  WWWkScycNMaiamzb_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  WWWkScycNMaiamzb_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  WWWkScycNMaiamzb_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  WWWkScycNMaiamzb_SystemCall_10_0_19042
	cmp word ptr [rax+0x120], 19043
	je  WWWkScycNMaiamzb_SystemCall_10_0_19043
	jmp WWWkScycNMaiamzb_SystemCall_Unknown
WWWkScycNMaiamzb_SystemCall_6_1_7600:          
	mov eax, 0x00a5
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_6_1_7601:          
	mov eax, 0x00a5
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_6_2_XXXX:          
	mov eax, 0x00af
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_6_3_XXXX:          
	mov eax, 0x00b0
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_10240:        
	mov eax, 0x00b3
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_10586:        
	mov eax, 0x00b4
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_14393:        
	mov eax, 0x00b6
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_15063:        
	mov eax, 0x00b9
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_16299:        
	mov eax, 0x00ba
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_17134:        
	mov eax, 0x00bb
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_17763:        
	mov eax, 0x00bc
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_18362:        
	mov eax, 0x00bd
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_18363:        
	mov eax, 0x00bd
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_19041:        
	mov eax, 0x00c1
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_19042:        
	mov eax, 0x00c1
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_10_0_19043:        
	mov eax, 0x00c1
	jmp WWWkScycNMaiamzb_Epilogue
WWWkScycNMaiamzb_SystemCall_Unknown:           
	ret
WWWkScycNMaiamzb_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NkuBbnmLpIlRkgSj*(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                   
NkuBbnmLpIlRkgSj_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NkuBbnmLpIlRkgSj_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NkuBbnmLpIlRkgSj_Check_10_0_XXXX
	jmp NkuBbnmLpIlRkgSj_SystemCall_Unknown
NkuBbnmLpIlRkgSj_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NkuBbnmLpIlRkgSj_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NkuBbnmLpIlRkgSj_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NkuBbnmLpIlRkgSj_SystemCall_6_3_XXXX
	jmp NkuBbnmLpIlRkgSj_SystemCall_Unknown
NkuBbnmLpIlRkgSj_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NkuBbnmLpIlRkgSj_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NkuBbnmLpIlRkgSj_SystemCall_6_1_7601
	jmp NkuBbnmLpIlRkgSj_SystemCall_Unknown
NkuBbnmLpIlRkgSj_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_19042
	cmp word ptr [rax+0x120], 19043
	je  NkuBbnmLpIlRkgSj_SystemCall_10_0_19043
	jmp NkuBbnmLpIlRkgSj_SystemCall_Unknown
NkuBbnmLpIlRkgSj_SystemCall_6_1_7600:          
	mov eax, 0x0023
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_6_1_7601:          
	mov eax, 0x0023
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_6_2_XXXX:          
	mov eax, 0x0024
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_6_3_XXXX:          
	mov eax, 0x0025
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_10240:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_10586:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_14393:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_15063:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_16299:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_17134:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_17763:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_18362:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_18363:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_19041:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_19042:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_10_0_19043:        
	mov eax, 0x0026
	jmp NkuBbnmLpIlRkgSj_Epilogue
NkuBbnmLpIlRkgSj_SystemCall_Unknown:           
	ret
NkuBbnmLpIlRkgSj_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc YxZNuSxVfOyuVhxK*(ProcessHandle: HANDLE, BaseAddress: PVOID, RegionSize: PSIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                            
YxZNuSxVfOyuVhxK_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  YxZNuSxVfOyuVhxK_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  YxZNuSxVfOyuVhxK_Check_10_0_XXXX
	jmp YxZNuSxVfOyuVhxK_SystemCall_Unknown
YxZNuSxVfOyuVhxK_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  YxZNuSxVfOyuVhxK_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  YxZNuSxVfOyuVhxK_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  YxZNuSxVfOyuVhxK_SystemCall_6_3_XXXX
	jmp YxZNuSxVfOyuVhxK_SystemCall_Unknown
YxZNuSxVfOyuVhxK_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  YxZNuSxVfOyuVhxK_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  YxZNuSxVfOyuVhxK_SystemCall_6_1_7601
	jmp YxZNuSxVfOyuVhxK_SystemCall_Unknown
YxZNuSxVfOyuVhxK_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_19042
	cmp word ptr [rax+0x120], 19043
	je  YxZNuSxVfOyuVhxK_SystemCall_10_0_19043
	jmp YxZNuSxVfOyuVhxK_SystemCall_Unknown
YxZNuSxVfOyuVhxK_SystemCall_6_1_7600:          
	mov eax, 0x004d
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_6_1_7601:          
	mov eax, 0x004d
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_6_2_XXXX:          
	mov eax, 0x004e
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_6_3_XXXX:          
	mov eax, 0x004f
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_10240:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_10586:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_14393:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_15063:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_16299:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_17134:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_17763:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_18362:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_18363:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_19041:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_19042:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_10_0_19043:        
	mov eax, 0x0050
	jmp YxZNuSxVfOyuVhxK_Epilogue
YxZNuSxVfOyuVhxK_SystemCall_Unknown:           
	ret
YxZNuSxVfOyuVhxK_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc osiboiBWRpRofhcq*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                          
osiboiBWRpRofhcq_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  osiboiBWRpRofhcq_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  osiboiBWRpRofhcq_Check_10_0_XXXX
	jmp osiboiBWRpRofhcq_SystemCall_Unknown
osiboiBWRpRofhcq_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  osiboiBWRpRofhcq_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  osiboiBWRpRofhcq_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  osiboiBWRpRofhcq_SystemCall_6_3_XXXX
	jmp osiboiBWRpRofhcq_SystemCall_Unknown
osiboiBWRpRofhcq_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  osiboiBWRpRofhcq_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  osiboiBWRpRofhcq_SystemCall_6_1_7601
	jmp osiboiBWRpRofhcq_SystemCall_Unknown
osiboiBWRpRofhcq_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  osiboiBWRpRofhcq_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  osiboiBWRpRofhcq_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  osiboiBWRpRofhcq_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  osiboiBWRpRofhcq_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  osiboiBWRpRofhcq_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  osiboiBWRpRofhcq_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  osiboiBWRpRofhcq_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  osiboiBWRpRofhcq_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  osiboiBWRpRofhcq_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  osiboiBWRpRofhcq_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  osiboiBWRpRofhcq_SystemCall_10_0_19042
	cmp word ptr [rax+0x120], 19043
	je  osiboiBWRpRofhcq_SystemCall_10_0_19043
	jmp osiboiBWRpRofhcq_SystemCall_Unknown
osiboiBWRpRofhcq_SystemCall_6_1_7600:          
	mov eax, 0x0037
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_6_1_7601:          
	mov eax, 0x0037
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_6_2_XXXX:          
	mov eax, 0x0038
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_6_3_XXXX:          
	mov eax, 0x0039
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_10240:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_10586:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_14393:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_15063:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_16299:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_17134:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_17763:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_18362:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_18363:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_19041:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_19042:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_10_0_19043:        
	mov eax, 0x003a
	jmp osiboiBWRpRofhcq_Epilogue
osiboiBWRpRofhcq_SystemCall_Unknown:           
	ret
osiboiBWRpRofhcq_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

