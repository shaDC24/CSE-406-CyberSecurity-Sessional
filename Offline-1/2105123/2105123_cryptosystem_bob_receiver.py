import socket
import importlib
import os
from datetime import datetime

aes=importlib.import_module("2105123_aes")
dh=importlib.import_module("2105123_dh")
fs=importlib.import_module("2105123_file_system_utils")

def start_bob_receiver(host, port,store_folder="received_files"):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"BOB(actually like server) is listening at {host}:{port}...")

    connection, address = server_socket.accept()
    print(f"Now Bob is connected by ALICE at {address}")


    # data = connection.recv(4096).decode()
    data=fs.receive_message(connection).decode()
    key_size,p_from_alice, g_from_alice, A_shared_key = data.split(',')
    key_size_in_bits=int(key_size)
    p = int(p_from_alice)
    g = int(g_from_alice)
    A = int(A_shared_key)
    print(f"Received key size is {key_size_in_bits}.")
    print(f"Received P={p}, g={g}, and A={A} from ALICE.")

    k_b = dh.generate_private_user_key(key_size_in_bits, p)
    B = dh.modular_expo(g, k_b, p)
    # connection.sendall(str(B).encode())
    fs.send_message_length_data(connection,str(B).encode())
    print(f"Bob is sending shared key={B} to ALICE.")

    s_b = dh.modular_expo(A, k_b, p)
    print(f"BOB's Shared Secret is computed.")
    aes_key = dh.derive_aes_key(s_b, key_size_in_bits)
    Nk, Nr, total_words = aes.initialize_parameter(key_size_in_bits) #CBC
    w = aes.key_expansion(list(aes_key), Nk, Nr, total_words)
    print("Bob is waiting for the filename from Alice.")
    file_name = fs.receive_message(connection).decode()    
    print("Bob is waiting for encrypted message from Alice.")
    ciphertext = fs.receive_message(connection)
    receive_time = datetime.now()
    print(f"{receive_time.strftime("%Y-%m-%d %H:%M:%S")} : Bob has received the ciphertext.")
    decrypted_bytes = aes.aes_cbc_decrypt(list(ciphertext), w, Nr)
    decryption_end_time=datetime.now()
    print(f"{decryption_end_time.strftime("%Y-%m-%d %H:%M:%S")} : Bob sides decryption successfully completed.")
    if file_name=="" or file_name==None:
        print(f"\nAt Bob's side : decrypted message from ALICE: {bytes(decrypted_bytes).decode()}")
    else :
        if not os.path.exists(store_folder):
            os.makedirs(store_folder)
        save_received_file_path=os.path.join(store_folder,"received_"+file_name)
        output_file=open(save_received_file_path,"wb")
        output_file.write(bytes(decrypted_bytes))
        output_file.close()
        print(100*"=")
        print(f"At Bob's side : the decrypted file is saved as '{save_received_file_path}'")

    

    connection.close()
    server_socket.close()

if __name__ == "__main__":

    SERVER_HOST = "127.0.0.1"
    SERVER_PORT = 65435
    choice="y"
    while choice=="y":
        start_bob_receiver(SERVER_HOST, SERVER_PORT)
        print("Received successfully from Alice. Do you continue to listen?")
        choice=input(f"Press y if yes or any key to exit : ").strip().lower()