import socket
import threading
import struct
from args import EnterData
from scapy.all import IP, TCP, UDP, ICMP, sr1, sr
from result import Result
from random import randint


def get_dns_request():
    return struct.pack("!HHHHHH", randint(1, 65500), 256, 1, 0, 0, 0) +\
        b"\x06anytask\x03org\x00\x00\x01\x00\x01"

def get_HTTP_request():
    return b'GET / HTTP/1.1\r\nHost: google.com\r\n'

def get_ECHO_request():
    return b'World'


REQUESTS = {
    'HTTP': get_HTTP_request,
    'DNS': get_dns_request,
    'ECHO': get_ECHO_request
}


def check_protocol(answer, request):
    if answer[:4] == b'HTTP':
        return 'HTTP'
    elif struct.unpack('!H', answer[:2]) == struct.unpack('!H', request[:2]):
        return 'DNS'
    elif answer == request:
        return 'ECHO'
    else:
        return '-'


def try_determinate_application_protocol_for_tcp(port):
    for request in REQUESTS.keys():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.settimeout(timeout)
                sock.connect((ip_address, port))
                req = REQUESTS[request]()
                sock.sendall(req)
                data = sock.recv(1023)
                prot = check_protocol(data, req)
                tcp_ports_app[port] = prot
                return
            except:
                continue
    tcp_ports_app[port] = '-'


def try_determinate_application_protocol_for_udp(port):
    for request in REQUESTS.keys():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.settimeout(timeout)
                sock.connect((ip_address, port))
                req = REQUESTS[request]()
                sock.sendall(req)
                data = sock.recv(1023)
                prot = check_protocol(data, req)
                udp_ports_app[port] = prot
                return
            except:
                continue
    udp_ports_app[port] = '-'


def close_tcp_connection(port):
    sr(IP(dst=ip_address) / TCP(dport=port, flags="AR"), timeout=timeout, verbose=0)


def scan_tcp_port(port):
    packet = IP(dst=ip_address) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=timeout, verbose=0)
    if response and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            time = round((response.time - packet.sent_time) * 1000)
            open_tcp_ports.append([port, time])


def scan_udp_port(port):
    packet = IP(dst=ip_address) / UDP(dport=port)
    answer = sr1(packet, timeout=timeout, verbose=0)
    if answer == None or answer.haslayer(UDP):
        open_udp_ports.append(port)
        
    elif(answer.haslayer(ICMP)):
        if(int(answer.getlayer(ICMP).type) == 3 and int(answer.getlayer(ICMP).code) == 3):
            return
			
        elif(int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,9,10,13]):
            return
    else:
        return


def scan_port(port, protocol):
    if protocol == 'tcp':
        scan_tcp_port(port)
        close_tcp_connection(port)
        if guess_protocol:
            try_determinate_application_protocol_for_tcp(port)
    elif protocol == 'udp':
        scan_udp_port(port)
        if guess_protocol:
            try_determinate_application_protocol_for_udp(port)
    else:
        raise ValueError("Invalid protocol")


def scan_ports(list_ports, protocol):
    threads = []
    for ports in list_ports:
        for port in ports:
            threads.append(threading.Thread(target=scan_port, args=(port, protocol), daemon=True))
            threads[-1].start()
            
        for thread in threads:
            thread.join()


def find_open_ports():
    for protocol in args.ports_by_protocol.keys():
        ports = [list(args.ports_by_protocol[protocol])[d:d+num_threads] 
                 for d in range(0, len(args.ports_by_protocol[protocol]), num_threads)]
        scan_ports(ports, protocol)


def determinate_protocols_and_print_result():
    result = []
    for tcp_port in open_tcp_ports:
        if guess_protocol:
            result.append(Result('tcp', tcp_port[0], tcp_port[1], tcp_ports_app[tcp_port[0]]))
        else:
            result.append(Result('tcp', tcp_port[0], tcp_port[1], ""))
    for udp_port in open_udp_ports:
        if guess_protocol:
            result.append(Result('udp', udp_port, -1, udp_ports_app[udp_port]))
        else:
            result.append(Result('udp', udp_port, -1, ""))

    print_result(result)
    
    
def print_result(result: list[Result]):
    for res in result:
        string = res.protocol + ' ' + str(res.port)
        if verbose and res.protocol == 'tcp':
            string += " " + str(res.time)
        if guess_protocol:
            string += ' ' + res.proto_app

        print(string)

def main():
    find_open_ports()
    determinate_protocols_and_print_result()


if __name__ == "__main__":
    args = EnterData().build()
    ip_address = args.ip
    timeout = args.timeout
    num_threads = args.num_threads
    verbose = args.verbose
    guess_protocol = args.guess_protocol

    open_udp_ports = []
    udp_ports_app = {}
    open_tcp_ports = []
    tcp_ports_app = {}
    main()
