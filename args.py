import argparse


class EnterData:
    def __init__(self):
        self.timeout = 2
        self.num_threads = 1
        self.verbose = False
        self.guess_protocol = False
        self.ip = None
        self.ports_by_protocol = {}

    def build(self):
        args = self.__parse_input_string()
        
        self.timeout = args.timeout
        self.num_threads = args.num_threads
        self.verbose = args.verbose
        self.guess_protocol = args.guess

        self.ip = args.ip_address
        self.ports_by_protocol = self.parse_ports(args.ports)
        return self
    
    def parse_ports(self, ports):
        ports_by_protocol = {'udp': set(), 'tcp': set()}
        for port in ports:
            if len(port.split('/')) < 2:
                ports_by_protocol[port] = set(range(0, 65355))
            else:
                proto, possible_ports = port.split('/')
                for range_ports in possible_ports.split(','):
                    start, end = 0, 0
                    if '-' not in range_ports:
                        start = end = int(range_ports)
                    else:
                        start, end = map(int, range_ports.split('-'))
                    end += 1
                    ports_by_protocol[proto] = ports_by_protocol[proto].union(set(range(start, end)))
        return ports_by_protocol
    
    def __parse_input_string(self):
        parser = argparse.ArgumentParser(description="Port scanner")
        
        parser.add_argument("ip_address", help="Target IP address")
        parser.add_argument("ports", nargs="+", help="Ports to scan in the format [tcp|udp[/[PORT|PORT-PORT],...]]")
        
        parser.add_argument("--timeout", type=int, default=2, help="Timeout for waiting for a response (default: 2s)")
        parser.add_argument("-j", "--num-threads", type=int, default=1, help="Number of threads for multithreaded implementation")
        parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
        parser.add_argument("-g", "--guess", action="store_true", help="Guess the application layer protocol")

        return parser.parse_args()