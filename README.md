# ShellcodeLoader

This is a C program that demonstrates loading and executing shellcode in memory on Windows using native NT API functions.

---

What it does

- Allocates RW memory with `NtAllocateVirtualMemory`  
- Changes memory protection to RX with `NtProtectVirtualMemory`  
- Executes shellcode by creating a new thread with `NtCreateThreadEx`

---

How to compile

- Open the project in Visual Studio  
- Set target architecture to x64 
- Build in Release mode  

---

How to run

- Run the compiled executable as Administrator on Windows  
- It should hit an INT3 trap, this is just a sample
---

How to use custom shellcode

You can replace the built-in shellcode with your own. Follow these steps carefully:

1. Obtain your shellcode  
   - I used the tool [msfvenom](https://www.metasploit.com/) or write your own assembly and assemble it into shellcode bytes.  
   - The shellcode must be a raw byte array without null bytes (if possible) for reliability.  

2. Format your shellcode as a C byte array  
   - Your shellcode should be in the format:  
     ```c
     unsigned char shellcode[] = "\xAA\xBB\xCC\xDD...";  
     ```
   - Each byte is represented as a hexadecimal escape sequence (`\x??`).  

3. Replace the existing shellcode in `loader.c`
   - Find the existing `unsigned char shellcode[] = ...` line near the top of the source file.  
   - Replace it with your own shellcode array.  

4. Update the size variable (optional)
   - The program uses `sizeof(shellcode)` automatically, so no manual size update is needed if you use a byte array.  

5.  Recompile the project  
   - Make sure to clean and rebuild in Visual Studio to include the new shellcode.  

6.  Run the program 
   - Run as Administrator and observe the behavior of your shellcode.  

---

 Important notes

- Test in a safe, isolated environment only! 
- Running arbitrary shellcode can crash your system or cause unwanted effects.  
- Always scan your shellcode for null bytes and invalid instructions.  
- Use a debugging tool to step through your shellcode safely.  

---

Disclaimer

This project is for educational purposes only. Use it responsibly in controlled lab environments. Never deploy unauthorized code on systems you do not own or have explicit permission to test.

---

