def send_message_length_data(socket,data:bytes):
    length=len(data).to_bytes(8,"big")
    socket.sendall(length+data)


def receive_exact_message(socket, total_bytes):
    buffer = b""
    while len(buffer) < total_bytes:
        chunk = socket.recv(total_bytes - len(buffer))
        if not chunk:
            print("Socket closed before all data has been received.")
            return None
        buffer+=chunk
    return buffer


def receive_message(socket):
    length_bytes = receive_exact_message(socket,8)
    if length_bytes is None:
        print("Before length prefix is received , socket has been closed.")
        return None
    length = int.from_bytes(length_bytes, "big")
    return receive_exact_message(socket, length)

