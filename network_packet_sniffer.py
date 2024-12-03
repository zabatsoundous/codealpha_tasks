import socket
import struct
import pyshark
import logging
import time
from colorama import Fore, Style

#global variables 
packet_count = 0 #for captured packets 
total_bytes = 0 # for captured bytes

# ip packet
def ip_packet(data):
    #extract ip header 
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20]) #20bytes
    version_ihl = ip_header[0]
    version = version_ihl >> 4#get ip version
    ihl = version_ihl & 0xF #the header lenght
    ttl = ip_header[5]  #time to live value
    protocol = ip_header[6] #tcp or udp or icmp
    src_ip = socket.inet_ntoa(ip_header[8]) #ip source
    dest_ip = socket.inet_ntoa(ip_header[9])#ip destintion
    return version, ihl, ttl, protocol, src_ip, dest_ip, data[ihl*4:]

#icmp
def icmp_packet(data):
    #header
    icmp_header = struct.unpack('!BBHHH', data[:8])#8 bytes
    icmp_type = icmp_header[0] #icmp type
    icmp_code = icmp_header[1] #code of icmp message
    checksum = icmp_header[2] #error cheking
    id = icmp_header[3] 
    seq = icmp_header[4] #squence number
    return icmp_type, icmp_code, checksum, id, seq, data[8:]

#tcp
def tcp_packet(data):
    #header
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])  #20 bytes
    src_port = tcp_header[0] #source port number
    dest_port = tcp_header[1] #destination port
    seq_num = tcp_header[2] #sequence number
    ack_num = tcp_header[3] #acknowledgement number
    data_offset = tcp_header[4] >> 4  #header lengh
    flags = tcp_header[5] #flags SYN, ACK,...
    window = tcp_header[6] #window size
    checksum = tcp_header[7] #error cheking
    urgent_pointer = tcp_header[8] #pointer if exist
    return src_port, dest_port, seq_num, ack_num, flags, data[data_offset*4:]

#display
def display(packet):
    global packet_count, total_bytes
    packet_count += 1
    total_bytes += len(packet) 
    #print the packet count and total byte count
    print(f"Packets Captured: {packet_count} | Total Bytes: {total_bytes}\n")
    #ethernet frame
    eth_layer = packet.eth
    eth_dest_mac = eth_layer.dst  #destination mac add from eth_layer that has all the eth packet
    eth_src_mac = eth_layer.src #source mac
    eth_protocol = eth_layer.type  #protocol type 
    #printing
    print(f"{Fore.RED}-------------------------------- Ethernet Frame --------------------------------{Style.RESET_ALL}")
    print(f"  destination MAC: {eth_dest_mac}")
    print(f"  source MAC: {eth_src_mac}")
    print(f"  protocol: {hex(int(eth_protocol, 16))}")

    #check if there is an ip packet
    if 'IP' in packet:
        ip_layer = packet.ip
        version = ip_layer.version  
        ttl = ip_layer.ttl 
        protocol = ip_layer.proto 
        src_ip = ip_layer.src 
        dest_ip = ip_layer.dst 
        print(f"\n{Fore.YELLOW}-------------------------------- IP Packet --------------------------------{Style.RESET_ALL}")
        print(f"  Version: {version}")
        print(f"  TTL: {ttl}")
        print(f"  Protocol: {protocol}")
        print(f"  Source IP: {src_ip}")
        print(f"  Destination IP: {dest_ip}")

        #if the protocole is icmp
        if protocol == 1: #ICMP
            icmp_layer = packet.icmp
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code 
            print(f"{Fore.PURPLE}-------------------------- ICMP Packet -------------------------{Style.RESET_ALL}")
            print(f"  Type: {icmp_type}")
            print(f"  Code: {icmp_code}")

        #if it s tcp
        elif protocol == 6:#tcp
            if 'TCP' in packet:
                tcp_layer = packet.tcp
                src_port = tcp_layer.srcport 
                dest_port = tcp_layer.dstport
                seq_num = tcp_layer.seq 
                ack_num = tcp_layer.ack 
                flags = tcp_layer.flags 
                print(f"{Fore.BLUE}-------------------------------- TCP Packet --------------------------------{Style.RESET_ALL}")
                print(f"  Source Port: {src_port}")
                print(f"  Destination Port: {dest_port}")
                print(f"  Sequence Number: {seq_num}")
                print(f"  Acknowledgement Number: {ack_num}")
                print(f"  Flags: {flags}")

    #break line
    print("\n" + "-"*50 + "\n")

#capturing the pckets 
def capture_packets():
    try:
        capture = pyshark.LiveCapture(interface='wi-fi 3')  #replace 'wi-fi 3' with your network interface name
        capture.apply_on_packets(display)#call to the display functioon
    except Exception as e:
        print(f"error capturing packets: {e}")
        logging.error(f"error capturing packets: {e}")

if __name__ == "__main__":
    capture_packets()  #start capturing packets 
