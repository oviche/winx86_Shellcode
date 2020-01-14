import pefile
import sys

if(len(sys.argv)!=2):
    print("Usage: python3 shellcode_Extractor.py shellcode.exe")
    exit(0)
byte_list=[]
file = pefile.PE(sys.argv[1])
wfile = open("shellcodebytes.txt","w+")
for section in file.sections:
    if(b'text' in section.Name):
       byte_list=section.get_data()
start=0
end = 0
check = True
for i in range(0,len(byte_list)):
    if(byte_list[i] == 0x90 and check):
        start =i
        check = False
    elif(byte_list[i] == 0x90 and check== False):
       end = i
       break;

ans = byte_list[start+1:end]
print("Length of shellcode is : ",len(ans),"bytes")

for i in range(0, len(ans)):
    wfile.write('\\x'+hex(ans[i]).replace("0x",""))
wfile.close()

print("shellcode bytes extracted successfully into shellcodebytes.txt ....")
