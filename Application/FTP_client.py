import pickle

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

from Send import *

MAX_BYTES = 4096
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
DNS_CLIENT_PORT = 1024
DNS_SERVER_PORT = 53
CLIENT_PORT = 20781
SERVER_PORT = 30413
PACKET_SIZE = 1024
WINDOW_SIZE = 4
TIMEOUT = 2
CC_RENO = b"reno"
LOCAL_IP = '127.0.0.1'
SERVER_ADDRESS = ('localhost', SERVER_PORT)  # A tuple to represent the server.
lock = threading.Lock()  # Lock for threading (receiving messages).
window_start = 0  # Starting index for the window.
next_seq = 0  # Next packet to send.


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Connect DHCP <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
def connectDHCP():
    # -------------------------------- Create a DHCP discover packet -------------------------------- #
    print("(*) Creating DHCP discover packet.")
    # Ethernet layer
    ethernet = Ether()
    ethernet.dst = 'ff:ff:ff:ff:ff:ff'  # Broadcast.
    # Network layer
    ip = IP()
    ip.src = '0.0.0.0'
    ip.dst = '255.255.255.255'
    # Transport layer
    udp = UDP()
    udp.sport = DHCP_CLIENT_PORT
    udp.dport = DHCP_SERVER_PORT
    # Application layer
    bootp = BOOTP()
    bootp.flags = 1  # Request type message.
    bootp.xid = 666666  # XID
    # DHCP type message
    dhcp = DHCP()
    dhcp.options = [("message-type", "discover"), "end"]

    # Constructing the Discover packet and sending it.
    discover_packet = ethernet / ip / udp / bootp / dhcp
    print("(*) Sending DHCP discover...")
    sendp(discover_packet)
    # -------------------------------- Wait For DHCP Offer Packet -------------------------------- #
    print("(*) Waiting for DHCP offer...")
    # Sniff only from DHCP server port an offer packet.
    while True:
        offer = sniff(count=1, filter="udp and (port 67)")
        if offer[0][4].options[0][1] == 2:
            break
    # Pull the client IP the DHCP server offered.
    client_ip = offer[0][3].yiaddr
    # Pull the DHCP server's IP.
    server_ip = offer[0][3].siaddr
    # Pull the DNS server's IP.
    dns_ip = offer[0][4].options[4][1]
    print("(+) Got a DHCP offer packet.")

    # -------------------------------- Create a DHCP request packet -------------------------------- #
    print("(*) Creating DHCP request packet.")
    # Ethernet layer
    ethernet = Ether()
    ethernet.dst = 'ff:ff:ff:ff:ff:ff'  # Broadcast.
    # Network layer
    ip = IP()
    ip.src = '0.0.0.0'
    ip.dst = '255.255.255.255'
    # Transport layer
    udp = UDP()
    udp.sport = DHCP_CLIENT_PORT
    udp.dport = DHCP_SERVER_PORT
    # Application layer
    bootp = BOOTP()
    bootp.flags = 1  # Request type message.
    bootp.xid = 666666  # XID
    # DHCP type message
    dhcp = DHCP()
    dhcp.options = [("message-type", "request"), ('requested_addr', client_ip), ('server_id', server_ip),
                    ('subnet_mask', '255.255.255.0'), "end"]

    # Constructing the request packet and sending it.
    request_packet = ethernet / ip / udp / bootp / dhcp
    sendp(request_packet)
    print("(+) Sent DHCP request.")

    # -------------------------------- Wait For DHCP ack Packet -------------------------------- #
    print("(*) Waiting for DHCP ACK...")
    # Sniff only from DHCP server port.
    sniff(count=1, filter="udp and port 67")
    print("(+) Got a DHCP ACK packet.")

    # -------------------------------- Return The New Client IP -------------------------------- #
    return client_ip, dns_ip


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Connect DNS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
def connectDNS(gui_object, client_ip, dns_ip):
    print("\n*********************************")
    print("(*) Connecting to DNS server...")

    # -------------------------------- Create a DNS request packet -------------------------------- #
    # Receive a domain name from the user.
    domain_name = gui_object.getDomain()
    print("(*) Creating DNS request packet.")
    # Network layer
    network_layer = IP(src=client_ip, dst=dns_ip)
    # Transport layer
    transport_layer = UDP(sport=DNS_CLIENT_PORT, dport=DNS_SERVER_PORT)
    # DNS layer
    dns = DNS(id=0xABCD, rd=1, qd=DNSQR(qname=domain_name))  # Recursive request (rd=1).

    # Constructing the request packet and sending it.
    request = network_layer / transport_layer / dns
    # -------------------------------- Send DNS Request -------------------------------- #
    send(request)
    print("(+) Sent the DNS request.")
    # -------------------------------- Receive DNS Response -------------------------------- #
    print("(*) Waiting for the DNS response...")
    answer = sniff(count=1, filter="udp and (port 1024)")
    print("(+) Received the DNS response.")
    # Print and return the answer from the DNS or repeat process if no valid IP was found.
    if answer[0][3].rcode != 3:
        gui_object.enable_buttons()
        print("(+) DNS answer: ", answer[0][3].an.rdata)
        return answer[0][3].an.rdata
    else:
        print("(-) DNS failed. Try again.")
        gui_object.clear_entry()
        gui_object.disable_buttons()
        return None


def uploadToServerRUDP(file_path, sendFunc):
    global next_seq, window_start
    # ---------------------------------- CREATE CLIENT SOCKET ----------------------------------#
    print("\n*********************************")
    print("(*) Creating the client socket...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Make the ports reusable.
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Setting timeout for the socket.
    client_socket.settimeout(TIMEOUT)
    # Binding address and port to the socket.
    try:
        client_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # ---------------------------------- 3 WAY HAND SHAKE ----------------------------------#
    client_socket.sendto("upload".encode(), SERVER_ADDRESS)
    print("(+) Notified the server we want to upload.")
    try:
        # Receiving SYN-ACK message from server.
        msg, addr = client_socket.recvfrom(PACKET_SIZE)
        if msg.decode() == "SYN-ACK":
            print("(+) Received SYN-ACK message.")
    except socket.error as e:
        print("(-) Timeout occurred: ", e)
        # Close the socket.
        client_socket.close()
        return
    client_socket.sendto("ACK".encode(), SERVER_ADDRESS)
    print("(+) Sent ACK message.")
    # In case where ACK didn't arrive to the server.
    try:
        # Receiving SYN-ACK message from server.
        msg, addr = client_socket.recvfrom(PACKET_SIZE)
        if msg.decode() == "NACK":
            print("(-) Received NACK message. Connection failed.")
            client_socket.close()
            return
    except socket.error as e:
        pass
    # ---------------------------------- SEND THE FILE NAME TO THE SERVER ----------------------------------#
    # Get the file name.
    file_name = os.path.basename(file_path)
    # Send the file's name.
    client_socket.sendto(file_name.encode(), SERVER_ADDRESS)
    print("(+) Sent the file's name to the server.")
    # ---------------------------------- READING THE FILE ----------------------------------#
    # Initializing variables to track reliability.
    seq_num = 0  # Current seq number.
    chunks = []  # List that holds all the file's chunks.
    print("(*) Reading the file...")
    with open(file_path, "rb") as file:
        while True:
            # Read the file's bytes in chunks.
            bytes_read = file.read(MAX_BYTES)
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
    # Send the number of chunks to be expected to the server.
    client_socket.sendto(str(num_of_chunks).encode(), SERVER_ADDRESS)
    print("(+) Sent the number of chunks to the server.")
    # ---------------------------------- START THREAD TO RECEIVE ACKS ----------------------------------#
    thread = threading.Thread(target=receiveACKS, args=(client_socket, chunks, sendFunc))
    thread.start()
    # ---------------------------------- SENDING FILE ----------------------------------#
    # While there is chunks to send.
    while window_start < num_of_chunks:
        # Sending all the packets in the current window.
        while WINDOW_SIZE > next_seq - window_start:
            if next_seq < num_of_chunks:
                chunk_bytes = pickle.dumps(chunks[next_seq])
                has_sent = sendFunc(client_socket, chunk_bytes, SERVER_ADDRESS)
                if has_sent is True:
                    print('(+) Sent packet #', next_seq)
                    next_seq += 1
                else:
                    print("(-) Didn't send packet #",next_seq)
            else:
                break
    # Make main thread to wait for the current thread to finish.
    thread.join()
    # Disable timeout on socket.
    client_socket.settimeout(None)
    # Resetting the values.
    window_start = 0
    next_seq = 0
    # Close the socket.
    client_socket.close()


def downloadFromServerRUDP(file_name, save_path):
    global next_seq
    # ---------------------------------- CREATE CLIENT SOCKET ----------------------------------#
    print("\n*********************************")
    print("(*) Creating the client socket...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Make the ports reusable.
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Setting timeout for the socket.
    client_socket.settimeout(TIMEOUT)
    # Binding address and port to the socket.
    try:
        client_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # ---------------------------------- 3 WAY HAND SHAKE ----------------------------------#
    client_socket.sendto("download".encode(), SERVER_ADDRESS)
    print("(+) Notified the server we want to download.")
    try:
        # Receiving SYN-ACK message from server.
        msg, addr = client_socket.recvfrom(PACKET_SIZE)
        if msg.decode() == "SYN-ACK":
            print("(+) Received SYN-ACK message.")
    except socket.error as e:
        print("(-) Timeout occurred: ", e)
    client_socket.sendto("ACK".encode(), SERVER_ADDRESS)
    print("(+) Sent ACK message.")
    # ---------------------------------- SEND THE FILE NAME TO THE SERVER ----------------------------------#
    client_socket.sendto(file_name.encode(), SERVER_ADDRESS)
    print("(+) Sent request to download:", file_name)
    # Create the file directory (where we want to download the file).
    file_directory = save_path + "/" + file_name
    # Disabling the timeout for the socket.
    client_socket.settimeout(None)
    # Receiving the number of expected chunks.
    expected_chunks, addr = client_socket.recvfrom(PACKET_SIZE)
    # ---------------------------------- RECEIVE THE FILE FROM THE SERVER ----------------------------------#
    with open(file_directory, "wb") as file:
        while next_seq < int(expected_chunks.decode()):
            data_pickel, addr = client_socket.recvfrom(MAX_BYTES*2)
            data = pickle.loads(data_pickel)
            print("(+) Received packet #", data[1])
            # If we received the packet expected.
            if data[1] == next_seq:
                print("(+) Received the expected packet. Sending ack for it.")
                # Updating the next expected sequence.
                next_seq += 1
                # Sending ACK for the packet
                ack = pickle.dumps(("ACK", data[1]))
                client_socket.sendto(ack, SERVER_ADDRESS)
                # Write to the file the data we just received
                file.write(data[0])
            # Packet loss occurred.
            else:
                print("(-) Got packet out of order. Starting Dup ACK.")
                # Sending Dup ACK.
                dup_ack = pickle.dumps(("DUP ACK", next_seq - 1))
                client_socket.sendto(dup_ack, SERVER_ADDRESS)
        print("(+) Done downloading file.")
    # Closing the file.
    file.close()
    # Resetting the value.
    next_seq = 0

    # Close the socket.
    client_socket.close()


def receiveACKS(client_socket, chunks, sendFunc):
    global window_start, next_seq
    while True:
        try:
            # Receiving an ACK from the server.
            msg, addr = client_socket.recvfrom(MAX_BYTES)
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
                has_sent = sendFunc(client_socket, chunk_bytes, SERVER_ADDRESS)
                if has_sent is True:
                    print("(+) Retransmitted packet #", receive[1] + 1)
                else:
                    print("(-) Didn't send packet #", receive[1] + 1)
                lock.release()
        except socket.timeout as e:
            lock.acquire()
            if window_start < len(chunks):
                print("(-) Timeout occurred. Need to resend packet #", window_start)
                next_seq = window_start
                lock.release()
            else:
                print("(+) Sent all packets successfully.")
                lock.release()
                return


def uploadToServerTCP(gui_object, file_path):
    # ---------------------------------- CREATE CLIENT SOCKET ----------------------------------#
    print("\n*********************************")
    # Create TCP socket.
    print("(*) Creating the client socket...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Make the ports reusable.
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Change the CC algorithm (only if using LINUX system).
    # client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, CC_RENO)
    # Binding address and port to the socket.
    try:
        client_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # Connect to the server.
    client_socket.connect(SERVER_ADDRESS)
    client_socket.send("upload".encode())
    print("(+) Notified the server we want to upload.")
    sleep(0.2)
    # ---------------------------------- SEND THE FILE TO THE SERVER ----------------------------------#
    # Get the file size.
    file_size = os.path.getsize(file_path)
    # Send the file's size.
    client_socket.send(str(file_size).encode())
    print("(+) Sent the file's size to the server.")
    sleep(0.2)
    # Get the file name.
    file_name = os.path.basename(file_path)
    # Send the file's name.
    client_socket.send(file_name.encode())
    print("(+) Sent the file's name to the server.")
    # Open and send the file to the server.
    with open(file_path, "rb") as file:
        seq_num = 0
        total_packets_to_send = file_size // MAX_BYTES
        print("(*) Sending the file...")
        while True:
            # Read the file's bytes in chunks.
            bytes_to_send = file.read(MAX_BYTES)
            # If we are done with sending the file.
            if not bytes_to_send:
                print("(+) Done with sending file.")
                break
            # Check if got to the half the file and ask if to stop.
            if seq_num == (total_packets_to_send // 2):
                option = gui_object.userUploadChoice()
                if option is False:
                    break
            # Sending the file in chunks.
            client_socket.sendall(bytes_to_send)
            print("Sent:", seq_num, "/", total_packets_to_send)
            seq_num += 1
    # Close the byte-stream.
    file.close()
    # Close the socket.
    client_socket.close()


def downloadFromServerTCP(file_name, save_path):
    # ---------------------------------- CREATE CLIENT SOCKET ----------------------------------#
    print("\n*********************************")
    # Create TCP socket.
    print("(*) Creating the client socket...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Make the ports reusable.
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Change the CC algorithm (only if using LINUX system).
    # client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, CC_RENO)
    # Binding address and port to the socket.
    try:
        client_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # Connect to the server.
    client_socket.connect(SERVER_ADDRESS)
    print("(+) Connected to the server.")
    client_socket.send("download".encode())
    print("(+) Notified the server we want to download.")
    sleep(0.2)
    # ---------------------------------- RECEIVE THE FILE FROM THE SERVER ----------------------------------#
    client_socket.send(file_name.encode())
    print("(+) Sent request to download:", file_name)
    # Create the file directory (where we want to download the file).
    file_directory = save_path + "/" + file_name
    sleep(0.2)
    with open(file_directory, "wb") as file:
        print("(*) Downloading the file...")
        while True:
            # Read the file's bytes in chunks.
            bytes_to_write = client_socket.recv(MAX_BYTES)
            # If we are done with sending the file.
            if not bytes_to_write:
                print("(+) Done with downloading file.")
                break
            # Write to the file the bytes we just received
            file.write(bytes_to_write)
    # Close the byte-stream.
    file.close()
    # Close the socket.
    client_socket.close()


def sendCommunicationType(protocol):
    print("\n*********************************")
    # Create UDP socket.
    protocol_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Make the ports reusable.
    protocol_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Binding address and port to the socket.
    try:
        protocol_socket.bind((LOCAL_IP, CLIENT_PORT))
        print("(+) Binding was successful.")
    except socket.error as e:
        print("(-) Binding failed:", e)
        exit(1)
    # Sending the server which protocol we choose.
    protocol_socket.sendto(protocol.encode(), SERVER_ADDRESS)
    print("(+) Sent the", protocol, "communication protocol to the server.")
    # Close the socket.
    protocol_socket.close()


if __name__ == '__main__':
    from Graphical_Interface.GUI import GUI

    CLIENT_IP, DNS_IP = connectDHCP()
    gui = GUI(CLIENT_IP, DNS_IP)
    gui.createGUI()
    gui.runGUI()
