import random
import time

def modular_expo(base,exp,mod):
    return pow(base,exp,mod)

def miller_rabin_primality_test(number,round_num=40):
    
    if number<2:
        return False
    if number<=3:
        return True
    if number%2 ==0:
        return False
    #number-1=(2^d)* r
    r=number-1
    d=0
    while r%2 ==0:
        r=r//2
        d+=1

    for i in range(round_num):
        a=random.randint(2,number-2)    
        x=modular_expo(a,r,number)
        if x==1 or x==number-1 :
            continue
        else:
            for _ in range(d-1):
                x=modular_expo(x,2,number)
                if x==(number-1):
                    break
     
        if x!=(number-1):
            return False   
    return True             

def generate_prime(key_size):
    while True:
        prime_candidate=random.randint(2**(key_size-1),2**(key_size)-1)
        prime_candidate|=1
        if miller_rabin_primality_test(prime_candidate):
            return prime_candidate

def test_generate_prime():
    p = generate_prime(16)
    print(f"P = {p}")
    print(f"Bit length correct: {2**15 <= p < 2**16}")
    print(f"Verify prime: {miller_rabin_primality_test(p, 40)}")

def generating_safe_prime(key):
    while True:
        q=generate_prime(key-1)
        p=2*q+1
        if miller_rabin_primality_test(p):
            return p,q  
        
def find_generator(p,q):
    while True:
        g=random.randint(2,p-2)
        if pow(g,q,p)!=1 and pow(g,2,p)!=1:
            return g  
def generate_private_user_key(key_size, p):
    low=min(2**(key_size-1), p - 2)
    k_a_candidate=random.randint(low, p - 2) 
    return k_a_candidate

def diffie_hellman_key_exchange(key_size,p,q,g):
    k_a=generate_private_user_key(key_size,p)
    start_A_time=time.perf_counter()
    A=modular_expo(g, k_a, p)
    end_A_time=time.perf_counter()
    compute_time_A=(end_A_time-start_A_time)*1000
    k_b=generate_private_user_key(key_size,p)
    start_B_time=time.perf_counter()
    B=modular_expo(g, k_b, p)
    end_B_time=time.perf_counter()
    compute_time_B=(end_B_time-start_B_time)*1000
    start_shared_time_A=time.perf_counter()
    s_a=modular_expo(B, k_a, p)
    end_shared_time_A=time.perf_counter()
    compute_shared_time_A=(end_shared_time_A-start_shared_time_A)*1000
    start_shared_time_B=time.perf_counter()
    s_b=modular_expo(A, k_b, p)
    end_shared_time_B=time.perf_counter()
    compute_shared_time_B=(end_shared_time_B-start_shared_time_B)*1000
    shared_time=(compute_shared_time_A+compute_shared_time_B)/2
    if(s_a==s_b):
        return s_a,compute_time_A,compute_time_B,shared_time
    else :
        return None

def running_key_exchange(key_size,p,q,g,trials_num=5):
    total_time_A=0
    total_time_B=0
    total_shared_time=0
    successful_trials_num=0
    s_a=None

    for i in range(trials_num):
        result=diffie_hellman_key_exchange(key_size,p,q,g)
        if result is None:
            continue
        s_a,compute_time_A,compute_time_B,shared_time=result
        total_time_A+=compute_time_A
        total_time_B+=compute_time_B
        total_shared_time+=shared_time
        successful_trials_num+=1
    
    if successful_trials_num==0:
        print("All diffie hellman trials are failed to produce matching shared secret.")
        return
    avg_time_A=total_time_A/successful_trials_num
    avg_time_B=total_time_B/successful_trials_num
    avg_shared_time=total_shared_time/successful_trials_num   
    return s_a,avg_time_A,avg_time_B,avg_shared_time  

def derive_aes_key(s, key_size_bits):
    key_size_bytes = key_size_bits // 8
    return (s % (2**key_size_bits)).to_bytes(key_size_bytes, "big")    
    
def generate_report():
    random.seed(42)
    key_size=[128,192,256]

    print(f"{'k':<6}{'A time':<15}{'B time':<15}{'Shared time':<15}{'Shared Key':<40}")
    for ks in key_size:
        p,q=generating_safe_prime(ks)
        g=find_generator(p,q)
        s_a,avg_time_A, avg_time_B, avg_shared_time = running_key_exchange(ks,p,q,g)
        shared_key_display = hex(s_a)
        print(f"{ks:<6}{avg_time_A:<15.6f}{avg_time_B:<15.6f}{avg_shared_time:<15.6f}{shared_key_display:<40}")
    
if __name__=="__main__":
    generate_report()