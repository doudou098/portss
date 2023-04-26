import nmap

class NetworkScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def discover_network(self, network):
        self.scanner.scan(hosts=network, arguments='-n -sP -PE -PA21,23,80,3389')
        hosts = self.scanner.all_hosts()
        return hosts

class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan_top_ports(self, ip_address):
        self.scanner.scan(ip_address, arguments='-sS -T4 -F --top-ports 10')
        open_ports = []
        for port in self.scanner[ip_address]['tcp'].keys():
            if self.scanner[ip_address]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
        return open_ports

    def scan_port_details(self, ip_address, port):
        self.scanner.scan(ip_address, port, arguments='-sV -O -A -T4')
        return self.scanner[ip_address]['tcp'][int(port)]