#!/usr/bin/env python3
#=========================================================#
# [+] Title: Simple Network Sniffer                       #
# [+] Script: Sniffy.py                                   #
# [+] Blog: http://pytesting.blogspot.com                 #
#=========================================================#

import socket
import sys
import struct
import time
import sqlite3
from optparse import OptionParser

class ip(object):
    """ This class deals with the ip header level"""
    
    def __init__(self, header):
        self.header=header
    def extract(self):
        """ Extract IP Header elements """
        
        """ unpack header into:
            |_ B(Version+IHL)|B(TOS)|H(TotalLength)|H(ID)
            |_ H(Flags+FragmentOffset)|B(TTL)|B(Protocol)|H(CheckSum)
            |_ I(Source)|I(Destination)
            Note: "R" used to hold the reserved bits"""
        
        unpacked=struct.unpack("!BBHHHBBHII", self.header)
        header=[]
        # Version+IHL
        header+=unpackBit("4b4b", unpacked[0])
        # TOS: precedence, delay, throughput, reliability, monetary cost, Reserved
        header+=unpackBit("3b1b1b1b1b1b", unpacked[1])[:-1] # omit Reserved
        # total length
        header+=[unpacked[2]]
        # datagram id
        header+=[unpacked[3]]
        # flags(reserved, df, mf), fragment offset
        header+=unpackBit("1b1b1b13b", unpacked[4])[1:] # omit Reserved
        # Time to live in seconds
        header+=[unpacked[5]]
        header+=[unpacked[6]]

        header+=[unpacked[7]]
        # Source IP Address
        source=struct.pack("!I", unpacked[8]) # Pack address in "\xNN\xNN\xNN\xNN" format
        source=socket.inet_ntoa(source)
        header+=[source]
        # Destination IP Address
        destination=struct.pack("!I", unpacked[9])
        destination=socket.inet_ntoa(destination)
        header+=[destination]
        return header
    
    def parse(self):
        header=self.extract()
        try:
            db=sqlite3.connect("ip.sqlite")
            print("IP Header:")
            print("|_ Version: %d"%header[0])
            print("|_ Internet Header Length: %d bytes"%(header[1]*4))
            print("|_ Type of Service:")
            querry=db.execute("SELECT description FROM precedence WHERE id=%d"%header[2])
            print("|___ Precedence: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM delay WHERE id=%d"%header[3])
            print("|___ Delay: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM throughput WHERE id=%d"%header[4])
            print("|___ Throughput: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM reliability WHERE id=%d"%header[5])
            print("|___ Reliability: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM monetary_cost WHERE id=%d"%header[6])
            print("|___ Monetary Cost: "+querry.fetchone()[0])
            print("|_ Total Length: "+hex(header[7]))
            print("|_ Identification: "+hex(header[8]))
            print("|_ Flags:")
            querry=db.execute("SELECT description FROM fragmentation WHERE id=%d"%header[9])
            print("|___ Fragmentation: "+querry.fetchone()[0])
            querry=db.execute("SELECT description FROM more_fragments WHERE id=%d"%header[10])
            print("|___ More Fragments?: "+querry.fetchone()[0])
            print("|_ Fragment Offset: "+hex(header[11]))
            print("|_ Time to Live: %d seconds"%header[12])
            querry=db.execute("SELECT description FROM protocol WHERE id=%d"%header[13])
            print("|_ Protocol: "+querry.fetchone()[0])
            print("|_ Header Checksum: "+hex(header[14]))
            print("|_ Source IP address: "+header[15])
            print("|_ Destination IP address: "+header[16])
            db.close()
        except:
            print("[-] Error: ip.sqlite database not found")



def asciiDump(data):
    print("  ", end="")
    for x in data:
        if x in range(32,127):
            print(chr(x), end="")
        else:
            print(".", end="")
    print() # new line
            
def dump(data):
    print("--- DATA DUMP ---")
    print("Offset(h)  ", end="")
    for i in range(16):
        print("%02X "%i, end="")
    print("\tASCII")
    line=0 # every line holds 16 bytes
    index=0 # index of the current line in data
    for i in range(len(data)):
        if i%16==0:
            asciiDump(data[index:i])
            index=i
            # print the new line address
            print("%08X   "%line, end="")
            line+=1
        print("%02X "%data[i], end="")

    # Padding
    i+=1
    while i%16:
        print("   ", end="")
        i+=1
    # Last line ASCII dump
    asciiDump(data[index:])
    print("--- END DUMP  ---")
    
def unpackBit(fmt, data):
    """ unpack data at the bit level """
    try:
        # strip "b" separated string into list
        elements=fmt.split("b")
        # get rid of the empty string added by split
        elements=elements[:-1]
        # str to int
        for i in range(len(elements)): 
            elements[i]=int(elements[i])
        # length in bits
        length=sum(elements, 0)
        # convert data to a binary string 
        binary=bin(data)
        # omit '0b' prefix
        binary=binary[2:]
        # paddings
        if length>len(binary):
            binary='0'*(length-len(binary))+binary
        if length!=len(binary):
            raise ValueError("Unmatched size of data")
    except ValueError as err:
        print("[-] Error: %s"%str(err))
        sys.exit(1)

    # List of unpacked Data
    uData=[] 
    for l in elements:
        # Convert the first l bits to decimal
        unpacked=int(binary[:l], 2)
        uData.append(unpacked)
        # git rid of the last unpacked data
        binary=binary[l:] 

    return uData

def sniff(sock):
    """ sniff a packet, parse it's header and dump the sniffed data """
    packet, address=sock.recvfrom(65565)
    ipheader=ip(packet[:20]) # IP Header
    ipheader.parse() # display IP header descriptions
    dump(packet[20:]) # dump data

def main():
    parser=OptionParser()
    parser.add_option("-n", dest="npackets", type="int",\
                      help="Number of packets to sniff")
    (options, args)=parser.parse_args()
    s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    try:
        # get the current Network Interface
        host=socket.gethostbyname(socket.gethostname())
        s.bind((host, 0))
        # Enable the Promiscuous mode
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        if options.npackets!=None:
            for i in range(options.npackets):
                sniff(s)
        else:
            while True:
                sniff(s)
    except socket.error as err:
        print("[-] Error: %s"%str(err))
    except KeyboardInterrupt:
        print("[+] Keyboard Interruption captured: Existing")
        
    # Disable the Promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    s.close()        

if __name__=="__main__":
    main()


