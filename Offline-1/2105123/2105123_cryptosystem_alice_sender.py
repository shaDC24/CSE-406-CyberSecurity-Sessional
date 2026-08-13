import socket
import importlib
import os
from datetime import datetime

aes=importlib.import_module("2105123_aes")
dh=importlib.import_module("2105123_dh")
fs=importlib.import_module("2105123_file_system_utils")

def start_alice_sender(server_host, server_port, key_size_in_bits, plaintext_message=None,file_path=None):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((server_host, server_port))
    print(f"ALICE is connected to BOB at {server_host}:{server_port}")


    p, q = dh.generating_safe_prime(key_size_in_bits)
    g = dh.find_generator(p, q)
    k_a = dh.generate_private_user_key(key_size_in_bits, p)
    A = dh.modular_expo(g, k_a, p)

    payload = f"{key_size_in_bits},{p},{g},{A}"
    fs.send_message_length_data(client_socket, payload.encode())
    #client_socket.sendall(payload.encode())
    print(f"Alice is sending P={p}, g={g}, and A={A} to BOB.")

    #data = client_socket.recv(4096).decode()
    data=fs.receive_message(client_socket).decode()
    B = int(data)
    print(f"Alice has received B={B} from BOB.")
    s_a = dh.modular_expo(B, k_a, p)
    print(f"ALICE's Shared Secret computed.")

    aes_key = dh.derive_aes_key(s_a, key_size_in_bits)

    Nk, Nr, total_words = aes.initialize_parameter(key_size_in_bits)
    w = aes.key_expansion(list(aes_key), Nk, Nr, total_words)
    if file_path is not None:
        input_file = open(file_path, "rb")
        file_bytes = input_file.read()
        input_file.close()
        plaintext_bytes = list(file_bytes)
        file_name = os.path.basename(file_path)
    else:    
        plaintext_bytes = list(plaintext_message.encode())
        file_name=""
    fs.send_message_length_data(client_socket, file_name.encode())    
    encryption_start_time=datetime.now()
    print(f"{encryption_start_time.strftime("%Y-%m-%d %H:%M:%S")} : From Alice side encryption has started")
    ciphertext = aes.aes_cbc_encrypt(plaintext_bytes, w, Nr)
    
    #client_socket.sendall(bytes(ciphertext))
    fs.send_message_length_data(client_socket,bytes(ciphertext))
    send_time=datetime.now()
    if file_path is not None:
        print(f"{send_time.strftime("%Y-%m-%d %H:%M:%S")} : Alice is sending encrypted file '{file_name}' to Bob.")
    else:    
        print(f"{send_time.strftime("%Y-%m-%d %H:%M:%S")} : Alice is sending encrypted message to BOB.")
    client_socket.close()


if __name__ == "__main__":
    print("Hi Alice . You are the sender and you are sending to Bob. Please input the following queries.")
    TARGET_HOST="127.0.0.1"
    TARGET_PORT=65435
    choice="y"
    while choice=="y":
        key_input = input("Input Key Size (128/192/256) [Default: 128]: ").strip()
        KEY_SIZE = int(key_input) if key_input else 128
        print("Do you want to send a Message or a File?")
        choice = input("Input M for message or F for file : ").strip().upper()
        if choice == 'F':
            FILE_PATH = input("Input the file path : ").strip()
            MESSAGE = None
            if not os.path.exists(FILE_PATH):
                print(f"Error: The file '{FILE_PATH}' does not exist!")
                exit(1)
        else:
            MESSAGE = input("Input your secret message: ").strip()
            FILE_PATH = None

        print(f"\nAlice is sending to Bob using the address {TARGET_HOST}:{TARGET_PORT}...")
        start_alice_sender(TARGET_HOST, TARGET_PORT, KEY_SIZE, MESSAGE, FILE_PATH)   
        print(f"The intended message or file has been sent successfully.")
        choice=input(f"Do you want to send more ? Press y if yes or any key to exit : ").strip().lower()

