import aes_helpers 
import time

one_word=32
word_length=4
MIX_MULTIPLIERS_UNIQUE_NUMBER={
    value
    for matrix in (aes_helpers.Mixer, aes_helpers.InvMixer)
    for row in matrix
    for value in row}

CACHE_GF_MULT_TABLE={
    m: [aes_helpers.gf_mult(m, b) for b in range(256)]
    for m in MIX_MULTIPLIERS_UNIQUE_NUMBER    
}


def normalize_key(key_str, key_size_bytes):
    key_bytes = list(key_str.encode())
    if len(key_bytes) < key_size_bytes:
        key_bytes += [0] * (key_size_bytes - len(key_bytes))   
    else:
        key_bytes = key_bytes[:key_size_bytes]              
    return key_bytes


def pkcs7_padding(data):
    required_padding = 16 - (len(data) % 16)
    if required_padding == 0:
        required_padding = 16  
    padding = [required_padding] * required_padding  
    return data + padding

def pkcs7_unpadding(data):
    if not data:
        print("Empty data can not be upadded.")
        return
    pad_value = data[-1]   
    if pad_value<1 or pad_value>16 or pad_value>len(data):
        print("Invalid padding")
        return
    if data[-pad_value:]!=[pad_value]*pad_value:
        print("Invalid padding")
        return 
    return data[:-pad_value]


def convert_plain_bytes_to_state(ascii_plain_text,state_matrix):
    for i in range(word_length):
        for j in range(word_length):
            state_matrix[i][j]=ascii_plain_text[j*word_length+i]
    return state_matrix  

def convert_state_to_plain_bytes(state_matrix):
    ascii_plain_text=[]
    for j in range(word_length):
        for i in range(word_length):
            ascii_plain_text.append(state_matrix[i][j])
    return ascii_plain_text     


def initialize_parameter(input_bit):
    Nk=input_bit//one_word
    Nr=Nk+6
    total_words=word_length*(Nr+1)
    return Nk,Nr,total_words

def xor_matrix(a_word,b_word):
    result=[]
    for i in range(word_length):
        result.append(a_word[i]^b_word[i])
    return result    

def g(word,r_num):
    rotated_left_shift=[]
    for i in range(1,word_length+1):
        rotated_left_shift.append(word[i%word_length])
    substituted = []
    for b in rotated_left_shift:
        substituted.append(aes_helpers.Sbox[b])
    substituted[0] = substituted[0] ^ aes_helpers.Rcon[r_num]  
    return substituted

def substitution_only(word):
    substituted = []
    for b in word:
        substituted.append(aes_helpers.Sbox[b])
    return substituted  

def key_expansion(text,Nk,Nr,total_words):
    w=[]
    for i in range(Nk):
        w.append(text[word_length*i:word_length*(i+1)])
    rcon_counter=1
    for i in range(Nk,total_words):
        tmp=list(w[i-1])
        if i%Nk==0:
            tmp=g(tmp,rcon_counter)
            rcon_counter+=1
        elif Nk>6 and i%Nk==4: 
            tmp = substitution_only(tmp)    
        new_word=xor_matrix(w[i-Nk],tmp)    
        w.append(new_word)
    return w


def sub_Bytes(state_matrix):
    new_state_matrix = [[0]*word_length for i in range(word_length)]
    for i in range(word_length):
        for j in range(word_length):
            new_state_matrix[i][j]=aes_helpers.Sbox[state_matrix[i][j]]
    return new_state_matrix     

def inverse_sub_Bytes(state_matrix):
    new_state_matrix = [[0]*word_length for i in range(word_length)]
    for i in range(word_length):
        for j in range(word_length):
            new_state_matrix[i][j]=aes_helpers.InvSbox[state_matrix[i][j]]
    return new_state_matrix  

def shift_rows(state_matrix):
    new_state_matrix = [[0]*word_length for i in range(word_length)]
    for row in range(word_length):
        for col in range(word_length):
            new_state_matrix[row][col]=state_matrix[row][(col+row)%word_length]
    return new_state_matrix      

def inverse_shift_rows(state_matrix):
    new_state_matrix = [[0]*word_length for i in range(word_length)]
    for row in range(word_length):
        for col in range(word_length):
            new_state_matrix[row][col]=state_matrix[row][(col-row)%word_length]
    return new_state_matrix   

def mix_column(state_matrix):
    new_state_matrix=[[0]*word_length for i in range(word_length)]
    for col in range(word_length):
        column=[]
        for row in range(word_length):
            column.append(state_matrix[row][col])
        for row in range(word_length):
            result=0
            for k in range(word_length):
                #result=result^(aes_helpers.gf_mult(aes_helpers.Mixer[row][k],column[k])) 
                result=result^(CACHE_GF_MULT_TABLE[aes_helpers.Mixer[row][k]][column[k]])   
            new_state_matrix[row][col]=result
    return new_state_matrix            

def inverse_mix_column(state_matrix):
    new_state_matrix=[[0]*word_length for i in range(word_length)]
    for col in range(word_length):
        column=[]
        for row in range(word_length):
            column.append(state_matrix[row][col])
        for row in range(word_length):
            result=0
            for k in range(word_length):
                #result=result^(aes_helpers.gf_mult(aes_helpers.InvMixer[row][k],column[k]))    
                result=result^(CACHE_GF_MULT_TABLE[aes_helpers.InvMixer[row][k]][column[k]])  
            new_state_matrix[row][col]=result
    return new_state_matrix     

def add_round_key(state_matrix,round_key_word):
    st_matrix=[[0]*word_length for i in range(word_length)]
    round_key_state=convert_plain_bytes_to_state(round_key_word,st_matrix)
    new_state_matrix=[[0]*word_length for i in range(word_length)]
    for row in range(word_length):
        for col in range(word_length):
            new_state_matrix[row][col]=state_matrix[row][col]^round_key_state[row][col]
    return new_state_matrix        

def get_round_key(w, round_index):
    round_key = []
    for i in range(word_length):
        round_key.extend(w[word_length*round_index+i])
    return round_key

def aes_encryption_block(plaintext_byte,w,Nr):
    new_state_matrix=[[0]*word_length for i in range(word_length)]
    state_matrix=convert_plain_bytes_to_state(plaintext_byte,new_state_matrix)

    round_key0=get_round_key(w,0)
    state_matrix=add_round_key(state_matrix,round_key0)

    for i in range(1,Nr):
        state_matrix=sub_Bytes(state_matrix)
        state_matrix=shift_rows(state_matrix)
        state_matrix=mix_column(state_matrix)
        round_key=get_round_key(w,i)
        state_matrix=add_round_key(state_matrix,round_key)
        # print(f"After Round {i}:")
        # for row in state_matrix:
        #     print([f"{b:02X}" for b in row])
    state_matrix=sub_Bytes(state_matrix)
    state_matrix=shift_rows(state_matrix)
    round_key=get_round_key(w,Nr)
    state_matrix=add_round_key(state_matrix,round_key)   

    ciphertext_bytes = convert_state_to_plain_bytes(state_matrix) 
    return ciphertext_bytes

def aes_decryption_block(cyphertext_byte,w,Nr):
    new_state_matrix=[[0]*word_length for i in range(word_length)]
    state_matrix=convert_plain_bytes_to_state(cyphertext_byte,new_state_matrix)

    round_key_Nr=get_round_key(w,Nr)
    state_matrix=add_round_key(state_matrix,round_key_Nr)
    state_matrix=inverse_sub_Bytes(state_matrix)
    state_matrix=inverse_shift_rows(state_matrix)

    for i in range(Nr-1, 0, -1):
        
        round_key=get_round_key(w,i)
        state_matrix=add_round_key(state_matrix,round_key)        
        state_matrix=inverse_mix_column(state_matrix)
        state_matrix=inverse_shift_rows(state_matrix)
        state_matrix=inverse_sub_Bytes(state_matrix)
        # print(f"After Round {i}:")
        # for row in state_matrix:
        #     print([f"{b:02X}" for b in row])
    round_key=get_round_key(w,0)
    state_matrix=add_round_key(state_matrix,round_key)   

    plaintext_bytes = convert_state_to_plain_bytes(state_matrix) 
    return plaintext_bytes

def aes_ecb_encrypt(plaintext_bytes, w, Nr):
    padded = pkcs7_padding(plaintext_bytes)
    ciphertext = []
    
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        encrypted_block = aes_encryption_block(block, w, Nr)
        ciphertext.extend(encrypted_block)
    
    return ciphertext
def aes_ecb_decrypt(ciphertext_bytes, w, Nr):
    plaintext = []
    
    for i in range(0, len(ciphertext_bytes), 16):
        block = ciphertext_bytes[i:i+16]
        decrypted_block = aes_decryption_block(block, w, Nr)
        plaintext.extend(decrypted_block)
    
    unpadded = pkcs7_unpadding(plaintext)
    return unpadded

def xor_bytes(block_a, block_b):
    result = []
    for i in range(len(block_a)):
        result.append(block_a[i] ^ block_b[i])
    return result

import os
def aes_cbc_encrypt(plaintext_bytes, w, Nr):
    padded = pkcs7_padding(plaintext_bytes)
    
    iv = list(os.urandom(16))   
    
    ciphertext = list(iv)  
    previous_block = iv
    
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        xored = xor_bytes(block, previous_block)
        encrypted_block = aes_encryption_block(xored, w, Nr)
        ciphertext.extend(encrypted_block)
        previous_block = encrypted_block   
    
    return ciphertext
def aes_cbc_decrypt(iv_and_ciphertext, w, Nr):
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]
    
    plaintext = []
    previous_block = iv
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decryption_block(block, w, Nr)
        xored = xor_bytes(decrypted_block, previous_block)
        plaintext.extend(xored)
        previous_block = block   
    unpadded = pkcs7_unpadding(plaintext)
    return unpadded


def print_hex(data):
    return ' '.join(f'{b:02x}' for b in data)

def bytes_to_ascii_safe(data):
    return ''.join(chr(b) for b in data)

def run_report(mode, key_str, plaintext_str, key_size_bits=128):
    print(f"\n{'='*25} AES / {mode} {'='*25}\n")

    Nk, Nr, total_words = initialize_parameter(key_size_bits)
    key_bytes = normalize_key(key_str, Nk * 4)
    print("Key:")
    print(f"In ASCII: {bytes(key_bytes).decode()}")
    print(f"In HEX: {print_hex(key_bytes)}\n")
    t0 = time.perf_counter()
    w = key_expansion(key_bytes, Nk, Nr, total_words)
    t1 = time.perf_counter()
    key_schedule_time = (t1 - t0) * 1000 
    plaintext_bytes = list(plaintext_str.encode())
    padded = pkcs7_padding(plaintext_bytes)
    print("Plain Text:")
    print(f"In ASCII: {plaintext_str}")
    print(f"In HEX: {print_hex(plaintext_bytes)}")
    print(f"In ASCII (After Padding): {bytes_to_ascii_safe(padded)}")
    print(f"In HEX (After Padding): {print_hex(padded)}\n")

    t0 = time.perf_counter()
    if mode == "ECB":
        ciphertext = aes_ecb_encrypt(plaintext_bytes, w, Nr)
    else:
        ciphertext = aes_cbc_encrypt(plaintext_bytes, w, Nr)
    t1 = time.perf_counter()
    encryption_time = (t1 - t0) * 1000

    print("Ciphered Text:")
    if mode == "CBC":
        print("(IV is the first 16 bytes, followed by the actual ciphertext)")
    print(f"In HEX: {print_hex(ciphertext)}")
    print(f"In ASCII: {bytes_to_ascii_safe(ciphertext)}\n")
    t0 = time.perf_counter()
    if mode == "ECB":
        raw_blocks = []
        for i in range(0, len(ciphertext), 16):
            raw_blocks.extend(aes_decryption_block(ciphertext[i:i+16], w, Nr))
        decrypted = pkcs7_unpadding(raw_blocks)
    else:
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        raw_blocks = []
        prev = iv
        for i in range(0, len(ct), 16):
            block = ct[i:i+16]
            db = aes_decryption_block(block, w, Nr)
            raw_blocks.extend(xor_bytes(db, prev))
            prev = block
        decrypted = pkcs7_unpadding(raw_blocks)
    t1 = time.perf_counter()
    decryption_time = (t1 - t0) * 1000

    print("Deciphered Text:")
    print("Before Unpadding:")
    print(f"In HEX: {print_hex(raw_blocks)}")
    print(f"In ASCII: {bytes_to_ascii_safe(raw_blocks)}")
    print("After Unpadding:")
    print(f"In ASCII: {bytes(decrypted).decode()}")
    print(f"In HEX: {print_hex(decrypted)}\n")

    print("Execution Time Details:")
    print(f"Key Schedule Time: {key_schedule_time} ms")
    print(f"Encryption Time: {encryption_time} ms")
    print(f"Decryption Time: {decryption_time} ms")


if __name__ == "__main__":

    print("This is the aes check file.")
    key_size=int(input("Input the key size :[128/192/256] "))
    key_str = input("Input the encryption key: ")
    msg=input("Input the message for encryption : ")
    run_report("CBC", key_str, msg,key_size)
    run_report("ECB", key_str, msg,key_size)
    # run_report("CBC", "BUET CSE21 Batch", "We need picnic",192)
    # run_report("ECB", "BUET CSE21 Batch", "We need picnic",192)
    # run_report("CBC", "BUET CSE21 Batch", "We need picnic",256)
    # run_report("ECB", "BUET CSE21 Batch", "We need picnic",256)
