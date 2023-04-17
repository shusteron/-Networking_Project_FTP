from random import randint
from time import sleep
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether

MAX_BYTES = 4096
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67


# -------------------------------- Generate An IP To Offer Clients -------------------------------- #
def generate_random_ip(ip_list):
    while True:
        client_ip = '192.' + '168.' + '1.' + str(randint(0, 255))
        if client_ip not in ip_list:
            ip_list.append(client_ip)
            return client_ip


# -------------------------------- Generate An IP For Broadcasting -------------------------------- #
def generate_highest_ip(ip_list):
    for i in range(0, 255):
        broadcast_ip = "192.168.1." + str(255-i)
        if broadcast_ip not in ip_list:
            ip_list.append(broadcast_ip)
            return broadcast_ip
    return '255.255.255.255'


# -------------------------------- Create A DHCP Offer Packet -------------------------------- #
def create_offer(server_ip, client_ip, broadcast_ip):
    print("(*) Creating DHCP offer packet...")
    # Ethernet layer
    ethernet = Ether()
    ethernet.dst = 'ff:ff:ff:ff:ff:ff'  # Broadcast.
    # Network layer
    ip = IP()
    ip.src = server_ip
    ip.dst = broadcast_ip
    # Transport layer
    udp = UDP()
    udp.sport = DHCP_SERVER_PORT
    udp.dport = DHCP_CLIENT_PORT
    # Application layer
    bootp = BOOTP()
    bootp.flags = 2  # Replay type message.
    bootp.yiaddr = client_ip  # Suggest random IP.
    bootp.siaddr = server_ip  # DHCP server IP.
    bootp.giaddr = '0.0.0.0'  # no relay agent.
    bootp.xid = 666666  # XID
    # DHCP type message
    dhcp = DHCP()
    dhcp.options = [("message-type", "offer"), ('server_id', server_ip), ('subnet_mask', '255.255.255.0'),
                    ('lease_time', 2000), ('name_server', '192.168.4.4'), "end"]

    # Constructing the offer packet and sending it.
    offer = ethernet / ip / udp / bootp / dhcp
    print("(+) Sending DHCP offer.")
    sendp(offer)


# -------------------------------- Create A DHCP ACK Packet -------------------------------- #
def create_ack(server_ip, client_ip, broadcast_ip):
    print("(*) Creating DHCP ACK packet...")
    # Ethernet layer
    ethernet = Ether()
    ethernet.dst = 'ff:ff:ff:ff:ff:ff'  # Broadcast.
    # Network layer
    ip = IP()
    ip.src = server_ip
    ip.dst = broadcast_ip
    # Transport layer
    udp = UDP()
    udp.sport = DHCP_SERVER_PORT
    udp.dport = DHCP_CLIENT_PORT
    # Application layer
    bootp = BOOTP()
    bootp.flags = 2  # Replay type message.
    bootp.yiaddr = client_ip  # Suggest random IP.
    bootp.siaddr = server_ip  # DHCP server IP.
    bootp.giaddr = '0.0.0.0'  # No relay agent.
    bootp.xid = 666666  # XID
    # DHCP type message
    dhcp = DHCP()
    dhcp.options = [("message-type", "ack"), "end"]

    # Constructing the ACK packet and sending it.
    ack_packet = ethernet / ip / udp / bootp / dhcp
    print("(+) Sending DHCP ACK.")
    sendp(ack_packet)


if __name__ == '__main__':
    print("(*) Starting DHCP server...")
    # Create a list of used IPs.
    IP_LIST = []
    # Generate IP for server.
    SERVER_IP = generate_random_ip(IP_LIST)

    print("(+) Server IP: ", SERVER_IP)
    # Keep accepting clients.
    while True:
        # Generate suggested IP for the next client.
        CLIENT_IP = generate_random_ip(IP_LIST)
        # Generate broadcast IP for the next client.
        BROADCAST_IP = generate_highest_ip(IP_LIST)
        print("(+) Next Client IP suggestion: ", CLIENT_IP)
        print("(+) Next Client IP broadcast: ", BROADCAST_IP, "\n")
        # -------------------------------- Wait For DHCP Discovery Packet -------------------------------- #
        print("(*) Waiting for DHCP discovery...")
        # Sniff only from DHCP client port.
        sniff(count=1, filter="udp and (port 68)")
        print("(+) Got a DHCP discovery packet.")
        # -------------------------------- Send DHCP Offer Packet -------------------------------- #
        create_offer(SERVER_IP, CLIENT_IP, BROADCAST_IP)
        # -------------------------------- Wait For DHCP Request Packet -------------------------------- #
        print("(*) Waiting for DHCP request...")
        # Sniff only from DHCP client port.
        sniff(count=1, filter="udp and (port 68)")
        print("(+) Got a DHCP request packet.\n")
        # -------------------------------- Send DHCP ACK Packet -------------------------------- #
        sleep(0.3)
        create_ack(SERVER_IP, CLIENT_IP, BROADCAST_IP)
        # Delete the broadcast IP since it is no longer in use.
        IP_LIST.remove(BROADCAST_IP)
        sleep(2)
