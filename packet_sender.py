import socket
import sys
import random
import time

def read_bytes_from_file(file):
    file = open(file, 'r')
    byte_list = []
    for line in file:
        line = line.split()
        for bits in line:
            if len(bits) == 2:
                byte_list.append(int(bits, 16))
    return byte_list

sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)

sent = 0

byte_list = read_bytes_from_file("test")

i = byte_list[47]
j = byte_list[46]
k = byte_list[45]
l = byte_list[44]
print(i,j,k,l)
while(1):
    time.sleep(.5)
    if i <= 207:
        i = i + 48
        byte_list[47] = i
        packet = bytes(byte_list)
        sock.sendto(packet, ('localhost' , 0))
    elif j < 255:
        j = j+1
        i = (i+48)-256
        byte_list[46] = j
        byte_list[47] = i
        packet = bytes(byte_list)
        sock.sendto(packet, ('localhost' , 0))
    elif k < 255:
        j = 0
        byte_list[46] = j
        k = k + 1
        byte_list[45] = k
        i = (i+48)-256
        byte_list[47] = i
        packet = bytes(byte_list)
        sock.sendto(packet, ('localhost' , 0))
    elif l < 255:
        k=0
        j=0
        l=l+1
        i = (i+48)-256
        i = byte_list[47]
        j = byte_list[46]
        k = byte_list[45]
        l = byte_list[44]
        packet = bytes(byte_list)
        sock.sendto(packet, ('localhost' , 0))
    else:
        break
print ("Sent packet")
print(i,j,k,l)

