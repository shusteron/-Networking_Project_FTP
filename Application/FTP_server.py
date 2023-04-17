import pickle
from time import sleep
from scapy.all import *

MAX_BYTES = 8192
CLIENT_PORT = 20781
SERVER_PORT = 30413
PACKET_SIZE = 1024
WINDOW_SIZE = 4
TIMEOUT = 2  # In seconds
CC_CUBIC = b"cubic"
LOCAL_IP = '127.0.0.1'
lock = threading.Lock()  # Lock for threading (receiving messages).
window_start = 0  # Starting index for the window.
next_seq = 0  # The sequence number of the next expected packet.


# Method to upload a file to the server using RUDP.
def uploadRUDP():
    global next_seq
    # Setting timeout for the socket.
    server_socket.settimeout(TIMEOUT)
    # ---------------------------------- 3 WAY HAND SHAKE ----------------------------------#
    print("\n<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>")
    print("(*) Establishing a RUDP connection and preparing to upload...")
    server_socket.sendto("SYN-ACK".encode(), client_address)
    print("(+) Sent SYN-ACK message.")
    try:
        # Receiving ACK message to complete establishing a connection.
        msg, addr = server_socket.recvfrom(PACKET_SIZE)
        if msg.decode() == "ACK":
            print("(+) Received ACK.")
    except socket.timeout as error:
        server_socket.sendto("NACK".encode(), client_address)
        print("(-) Timeout occurred - sending NACK:", error)
        # Disabling the timeout for the socket.
        server_socket.settimeout(None)
        return
    print("(+) Connection established with: ", addr)
    # Disabling the timeout for the socket.
    server_socket.settimeout(None)
    # Receiving the file name from the client.
    file_name, addr = server_socket.recvfrom(PACKET_SIZE)
    # Create the file directory (where we want to upload the file).
    file_directory = "../Domains/" + domain.decode() + "/" + file_name.decode()
    # Receiving the number of expected chunks.
    expected_chunks, addr = server_socket.recvfrom(PACKET_SIZE)
    # ---------------------------------- RECEIVE THE FILE FROM THE CLIENT ----------------------------------#
    with open(file_directory, "wb") as file:
        while next_seq < int(expected_chunks.decode()):
            data_pickel, addr = server_socket.recvfrom(MAX_BYTES)
            data = pickle.loads(data_pickel)
            print("(+) Received packet #", data[1])
            # If we received the packet expected.
            if data[1] == next_seq:
                print("(+) Received the expected packet. Sending ack for it.")
                # Updating the next expected sequence.
                next_seq += 1
                # Sending ACK for the packet
                ack = pickle.dumps(("ACK", data[1]))
                server_socket.sendto(ack, client_address)
                # Write to the file the data we just received
                file.write(data[0])
            # Packet loss occurred.
            else:
                print("(-) Got packet out of order. Starting Dup ACK.")
                # Sending Dup ACK.
                dup_ack = pickle.dumps(("DUP ACK", next_seq - 1))
                server_socket.sendto(dup_ack, client_address)
        print("(+) Done uploading file.")
    # Closing the file.
    file.close()
    # Resetting the value.
    next_seq = 0


# Method to send a file to the client using RUDD.
def downloadRUDP():
    global next_seq, window_start
    # Setting timeout for the socket.
    server_socket.settimeout(TIMEOUT)
    print("\n<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>")
    print("(*) Establishing a RUDP connection and preparing to download...")
    # ---------------------------------- 3 WAY HAND SHAKE ----------------------------------#
    server_socket.sendto("SYN-ACK".encode(), client_address)
    print("(+) Sent SYN-ACK message.")
    try:
        # Receiving ACK message to complete establishing a connection.
        msg, addr = server_socket.recvfrom(PACKET_SIZE)
        if msg.decode() == "ACK":
            print("(+) Received ACK.")
    except socket.timeout as error:
        print("(-) Timeout occurred.", error)
        return
    print("(+) Connection established with: ", addr)
    sleep(0.2)
    try:
        # Receive the file's name that the client wants to download from the domain.
        file_name, addr = server_socket.recvfrom(PACKET_SIZE)
        print("(+) File name to download:", file_name.decode())
        # Create the file directory (the location of the requested file).
        file_path = "../Domains/" + domain.decode() + "/" + file_name.decode()
    except socket.timeout as error:
        print("(-) Timeout occurred.", error)
        return
    # ---------------------------------- READING THE FILE ----------------------------------#
    # Initializing variables to track reliability.
    seq_num = 0  # Current seq number.
    chunks = []  # List that holds all the file's chunks.
    print("(*) Reading the file...")
    with open(file_path, "rb") as file:
        while True:
            # Read the file's bytes in chunks.
            bytes_read = file.read(MAX_BYTES//2)
            # If we are done with sending the file.
            if not bytes_read:
                print("(+) Done with reading file.")
                break
            # Creating a tuple to send for the current chunk of data.
            chunk = (bytes_read, seq_num)
            # Adding the chunk to the list.
            chunks.append(chunk)
            # Increasing the seq_num by one.
            seq_num += 1
    # Close the byte-stream.
    file.close()
    # Saving the size of the file.
    num_of_chunks = len(chunks)
    # Send the number of chunks to be expected to the client.
    print(num_of_chunks)
    server_socket.sendto(str(num_of_chunks).encode(), client_address)
    print("(+) Sent the number of chunks to the server.")
    # ---------------------------------- START THREAD TO RECEIVE ACKS ----------------------------------#
    thread = threading.Thread(target=receiveACKS, args=(server_socket, chunks))
    thread.start()
    # ---------------------------------- SENDING FILE ----------------------------------#
    # While there is chunks to send.
    while window_start < num_of_chunks:
        # Sending all the packets in the current window.
        while WINDOW_SIZE > next_seq - window_start:
            if next_seq < num_of_chunks:
                chunk_bytes = pickle.dumps(chunks[next_seq])
                server_socket.sendto(chunk_bytes, client_address)
                print('(+) Sent packet #', next_seq)
                next_seq += 1
            else:
                break
    # Make main thread to wait for the current thread to finish.
    thread.join()
    # Disabling the timeout for the socket.
    server_socket.settimeout(None)
    # Resetting the values.
    window_start = 0
    next_seq = 0


def receiveACKS(server_socket, chunks):
    global window_start, next_seq
    while True:
        try:
            # Receiving an ACK from the client.
            msg, addr = server_socket.recvfrom(MAX_BYTES//2)
            receive = pickle.loads(msg)
            print("(+) Receive ACK for packet #:", receive[1])
            # If we got an ACK for a packet in the window.
            if window_start <= receive[1]:
                lock.acquire()
                # Updating the start index of the window.
                print("(+) Moving window by one.")
                window_start = receive[1] + 1
                lock.release()
            else:
                lock.acquire()
                print("(-) Didn't receive ack for packet #:", receive[1] + 1)
                chunk_bytes = pickle.dumps(chunks[receive[1] + 1])
                server_socket.sendto(chunk_bytes, client_address)
                print("(+) Retransmitted packet #", receive[1] + 1)
                lock.release()
        except socket.timeout:
            lock.acquire()
            if window_start < len(chunks):
                print("(-) Timeout occurred. Need to resend packet #", window_start)
                next_seq = window_start
                lock.release()
            else:
                print("(+) Sent all packets successfully.")
                lock.release()
                return


# Method to upload a file to the server using TCP.
def uploadTCP():
    print("\n<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>")
    print("(*) Establishing a TCP connection and preparing to upload...")
    file_size = int(connection.recv(PACKET_SIZE).decode())
    print("(+) Received the file's size.")
    print("(+) File size:", file_size, "bytes")
    file_name = connection.recv(PACKET_SIZE).decode()
    print("(+) Received the file's name.")
    print("(+) File name:", file_name)
    # Create the file directory (where we want to upload the file).
    file_directory = "../Domains/" + domain.decode() + "/" + file_name
    # ---------------------------------- RECEIVE THE FILE FROM THE CLIENT ----------------------------------#
    with open(file_directory, "wb") as file:
        while True:
            # Read the file's bytes in chunks.
            bytes_to_write = connection.recv(MAX_BYTES)
            # If we are done with sending the file.
            if not bytes_to_write:
                print("(+) Done.")
                file.close()
                break
            # Write to the file the bytes we just received
            file.write(bytes_to_write)
    # Close the connection.
    connection.close()


# Method to send a file to the client using TCP.
def downloadTCP():
    print("\n<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>")
    print("(*) Establishing a TCP connection and preparing to download...")
    # Receive the file's name that the client wants to download from the domain.
    file_name = connection.recv(PACKET_SIZE).decode()
    print("(+) File name to download:", file_name)
    # Create the file directory (the location of the requested file).
    file_path = "../Domains/" + domain.decode() + "/" + file_name
    sleep(0.2)
    # ---------------------------------- SEND THE FILE TO THE CLIENT ----------------------------------#
    with open(file_path, "rb") as file:
        print("(*) Sending the file...")
        while True:
            # Read the file's bytes in chunks.
            bytes_to_send = file.read(MAX_BYTES)
            # If we are done with sending the file.
            if not bytes_to_send:
                print("(+) Done with sending file.")
                break
            # Sending the file in chunks.
            connection.send(bytes_to_send)
    # Close the connection.
    connection.close()


if __name__ == "__main__":
    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RECEIVE THE PROTOCOl <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    # Starting server.
    print("(*) Starting application server...")
    # Create UDP socket to check which protocol to use.
    protocol_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        protocol_socket.bind((LOCAL_IP, SERVER_PORT))
        print("(+) Binding was successful with protocol socket.")
    except socket.error as e:
        print("(-) Binding failed with protocol socket:", e)
        exit(1)
    print("(*) Waiting for the user to choose protocol for communication...")
    # Getting from the client the type of the communication.
    protocol_choice, addr = protocol_socket.recvfrom(PACKET_SIZE)
    # Printing which protocol the user choose.
    print("(*) The user choose to communicate using " + protocol_choice.decode() + ".")
    print("\n*********************************")
    # Close the socket.
    protocol_socket.close()

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RECEIVE THE DOMAIN <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    # Create UDP socket to check what domain to connect.
    domain_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        domain_socket.bind((LOCAL_IP, SERVER_PORT))
        print("(+) Binding was successful with domain socket.")
    except socket.error as e:
        print("(-) Binding failed with domain socket:", e)
        exit(1)
    print("(*) Waiting for the user to enter domain...")
    # Getting from the client the type of the communication.
    domain, addr = domain_socket.recvfrom(PACKET_SIZE)
    # Printing which protocol the user choose.
    print("(+) Connected to : " + domain.decode())
    print("\n*********************************")
    # Close the socket.
    domain_socket.close()

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RUDP PROTOCOL HANDLE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    if protocol_choice.decode() == "RUDP":
        # Create UDP socket.
        print("(*) Creating the server socket (RUDP)...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Make the ports reusable.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Representation of the client's info.
        client_address = ('localhost', CLIENT_PORT)
        # Binding address and port to the socket.
        try:
            server_socket.bind((LOCAL_IP, SERVER_PORT))
            print("(+) Binding was successful.")
        except socket.error as e:
            print("(-) Binding failed:", e)
            exit(1)
        try:
            while True:
                print("(*) Listening...")
                request, address = server_socket.recvfrom(MAX_BYTES)
                if request.decode() == "upload":
                    uploadRUDP()
                if request.decode() == "download":
                    downloadRUDP()
        finally:
            # Closing the server socket.
            server_socket.close()

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> TCP PROTOCOL HANDLE <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #

    if protocol_choice.decode() == "TCP":
        # Create TCP socket.
        print("(*) Creating the server socket (TCP)...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Make the ports reusable.
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Change the CC algorithm (only if using LINUX system).
        # server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, CC_CUBIC)
        # Representation of the client's info.
        client_address = ('localhost', CLIENT_PORT)
        # Binding address and port to the socket.
        try:
            server_socket.bind((LOCAL_IP, SERVER_PORT))
            print("(+) Binding was successful.")
        except socket.error as e:
            print("(-) Binding failed:", e)
            exit(1)
        # Allow 100 people at max to connect to the server.
        server_socket.listen(100)
        try:
            while True:
                print("\n(*) Waiting for request...")
                connection, address = server_socket.accept()
                request = connection.recv(PACKET_SIZE)
                if request.decode() == "upload":
                    print("(+) Client choose to upload.")
                    uploadTCP()
                elif request.decode() == "download":
                    print("(+) Client choose to download.")
                    downloadTCP()
        finally:
            # Closing the server socket.
            server_socket.close()
