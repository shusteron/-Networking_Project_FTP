import random
from time import sleep


# A method to send a message to the address normally using socket.
def regularSend(socket, message, address):
    socket.sendto(message, address)
    return True


# A method to send with delay.
def delaySend(socket, message, address):
    sleep(2)
    socket.sendto(message, address)
    return True


# A method that illustrate packet loss with probability.
def packetLossSend(socket, message, address):
    # Generate random number between zero to one.
    chance = random.random()
    # If the probability is larger than 0.5 we send the packet else we don't (this simulates packet loss).
    if chance > 0.5:
        socket.sendto(message, address)
        return True
    else:
        return False
