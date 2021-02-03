#!/usr/bin/env python3

from enum import IntEnum
from typing import Union

import socket
import argparse
import atexit

import re

class PacketType(IntEnum):
    AUTH = 3
    EXECCOMMAND = 2
    AUTH_RESPONSE = 2 # Someone made an oops
    RESPONSE_VALUE = 0

def buildpacket(packet_id: int, packet_type: PacketType, body: Union[bytes, str]):
    if not isinstance(body, bytes):
        body = body.encode('ascii')

    if b'\x00' in body:
        raise ValueError("Body cannot contain null bytes")
    
    size = len(body) + 10
    if size > 4096:
        raise ValueError("Body is too long for packet")

    packet = b''.join([
        size.to_bytes(4, 'little', signed=True),
        packet_id.to_bytes(4, 'little', signed=True),
        packet_type.to_bytes(4, 'little', signed=True),
        body,
        b'\x00\x00'
    ])

    return packet

def readpacket(file):
    size = int.from_bytes(file.read(4), 'little', signed=True)
    packet = file.read(size)

    packet_id = int.from_bytes(packet[0:4], 'little', signed=True)
    packet_type = PacketType.from_bytes(packet[4:8], 'little', signed=True)
    body = packet[8:-2]

    # if packet[-1] != b'\x00':
    #     raise ValueError("Packet must end with null byte")

    # if packet[-2] != b'\x00':
    #     raise ValueError("Packet body must end with null byte")

    return packet_id, packet_type, body

def removecolor(b):
    return re.sub(rb'\xc2\xa7.', b'', b)

parser = argparse.ArgumentParser(description='An interface to the Source RCON protocol')
parser.add_argument('host', help="The host to connect to")
parser.add_argument('port', help="The port to connect to on host", type=int)
parser.add_argument('password_file', help="The file containing the password")
parser.add_argument('command', nargs='+', help="The command to be run")

if __name__ == '__main__':
    args = parser.parse_args()
    seqnum = 0

    sock = socket.create_connection((args.host, args.port))
    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    atexit.register(sock.close)

    sockfile = sock.makefile(mode='rwb', buffering=0)

    with open(args.password_file, 'r') as f:
        pword = f.read()

    sockfile.write(buildpacket(seqnum, PacketType.AUTH, pword))
    seqnum += 1

    auth, _, _ = readpacket(sockfile)

    if auth == -1:
        print("Invalid password")
        exit(1)

    command = ' '.join(args.command)
    sockfile.write(buildpacket(seqnum, PacketType.EXECCOMMAND, command))
    print(removecolor(readpacket(sockfile)[2]).decode('ascii'))
