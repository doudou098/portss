

import socket
import threading
import nmap
from libnmap.parser import NmapParser
class PortScanner:
    """
    A network scanner class that can be used to scan a network for up hosts and open ports.
    
    Args:
        ip_range: The range of IP addresses to scan.
        timeout: The timeout in seconds for each connection attempt.
    
    Attributes:
        found_hosts: A set of the up hosts found by the scanner.
        open_ports: A list of the open ports found by the scanner.
        vulnerabilities: A list of the vulnerabilities found by the scanner.
    """
    
    def __init__(self, ip, timeout=1):
        self.ip = ''
        self.timeout = timeout
        self.found_hosts = set()
        self.open_ports = []
        self.vulnerabilities = []
        self.scanner = nmap.PortScanner()
        
    
    
    def network_discovery(self):
        ip = input("Enter IP address to scan (e.g. 192.168.1.0): ")
        subnet = input("Enter the subnet you want to scan (e.g. 24): ")
        network_address = ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2]
        ip_list = []
        for i in range(1, 256):
            ip = network_address + '.' + str(i)
            ip_list.append(ip)
        self.scanner.scan(hosts=' '.join(ip_list), arguments='-n -sP')
        hosts_list = [(x, self.scanner[x]['status']['state']) for x in self.scanner.all_hosts()]
        print("Active devices:")
        for host, status in hosts_list:
            if status == 'up':
                print(host)
                ip_list.append(ip)
        return ip_list
    
    def scan_ports(self, ip_address, ports):
        """
        This method scans the specified IP address for the specified ports.
        
        Args:
            ip_address: The IP address to scan.
            ports: A list of ports to scan.
        
        Returns:
            A list of open ports.
        """

        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((ip_address, port))
                    open_ports.append(port)
            except:
                pass

        return open_ports
    
    def top_ports(self):
        """
        This method scans the top ports and displays which ports are open,
        as well as what service is running on each open port. The user should
        then have the option to see more details about the service running
        on a chosen port. If the user chooses to see more details, the method
        should print the version of the service running on the chosen port.
        Otherwise, it should display the menu again.
        """
        while True:
            ip = input("Enter an IP address to scan: ")
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143,
                    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

            open_ports = self.scan_ports(ip, ports)
            if not open_ports:
                print("No open ports found on {}".format(ip))
                break

            print("Open ports on {}:".format(ip))
            for port in open_ports:
                print("    Port {}: {}".format(port, self.get_service_name(port)))
            while True:
                option = input("Enter a port number for more details or 'q' to quit: ")
                if option == 'q':
                    return open_ports

                try:
                    port = int(option)
                    if port not in open_ports:
                        print("Port {} is not open on {}".format(port, ip))
                        continue
                    service_name = self.get_service_name(port)
                    version = self.get_service_version(ip, port)
                    if version:
                        print("Version information for {} running on port {}: {}".format(service_name, port, version))
                    else:
                        print("Version information for {} running on port {} is not available".format(service_name, port))
                except ValueError:
                    print("Invalid input, please enter a valid port number or 'q' to quit")
                    continue
    
    def get_service_name(self, port):
        try:
            services = socket.getservbyport(port)
            return services
        except OSError:
            return "Unknown"

    def get_service_version(self, ip, port):
        try:
            self.scanner.scan(ip, str(port))
            return self.scanner[ip]['tcp'][port]['product'] + " " + self.scanner[ip]['tcp'][port]['version']
        except KeyError:
            return "Unknown"
        
    def targeted_scan(self):
        """
        This method scans a target IP address for a specified port number.
        
        Returns:
            A list of tuples representing the open ports and services running on them, and a list of vulnerabilities for each service.
        """
        ip = input("Enter target IP address: ")
        port = int(input("Enter port number to scan: "))

        # Try connecting to the target IP and port
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect_ex((ip, port))
                self.open_ports.append(port)
                service = self.get_service_name(port)
                print(f"Port {port} is open: {service}")
                choice = input("Do you want to see more details about the service? (y/n): ")
                
                if choice.lower() == 'y':
                    version = self.get_service_version(ip, port)
                    print(f"Version of {service} running on port {port}: {version}")
                elif choice.lower() == 'n':
                    return self.menu
                else:
                    print('invalid input')
            
        except socket.timeout:
            print(f"Port {port} is closed")

        return self.open_ports
    
    def scan_all_ports(self):
        """
        This method scans all TCP ports and displays which ports are open.
        """
        ip = input("Enter target IP address: ")
        for ip in self.found_hosts:
            for port in range(1, 65536):
                threading.Thread(target=self.scan_port, args=(ip, port)).start()
                
        # Wait for all threads to complete before continuing
        for thread in threading.enumerate():
            if thread != threading.current_thread():
                thread.join()
                
        # Print open ports
        print("\nOpen ports:")
        for port in self.open_ports:
            print(f"{port} is open.")
            


    def vulnerability_scan(self, ip_address):
        scanner = nmap.PortScanner()
        scanner.scan(ip_address, arguments='-Pn -sS -A -sC')
        xml_output = scanner.get_nmap_last_output()
        nmap_report = NmapParser.parse_fromstring(xml_output)
        vulnerabilities = []
        xml_output = scanner.get_nmap_last_output()

        for host in nmap_report.hosts:
            for service in host.services:
                for script in service.scripts_results:
                    if 'VULNERABLE' in script['output']:
                        vulnerabilities.append((host.address, service.protocol, service.port, script['id']))

        return vulnerabilities

        
    
    def menu(self):
        """
        This method displays the menu and prompts the user for their choice.
        """
        while True:
            print("\nMenu:")
            print("1. Network discovery")
            print("2. Top ports scan")
            print("3. Targeted scan")
            print("4. Scan all ports")
            print("5. Vulnerability scan")
            print("6. Quit")

            choice = input("Enter your choice (1-6): ")
            if choice == "1":
                self.network_discovery()
            elif choice == "2":
                self.top_ports()
            elif choice == "3":
                self.targeted_scan()
            elif choice == "4":
                self.scan_all_ports()
            elif choice == "5":
                ip_address = input("Enter IP address to scan for vulnerabilities: ")
                vulnerabilities = self.vulnerability_scan(ip_address)
                print("Vulnerabilities found:")
                for vulnerability in vulnerabilities:
                    print(vulnerability)
            elif choice == "6":
                break
            else:
                print("Invalid choice, please try again.")


if __name__ == '__main__':
    scanner = PortScanner('ip')
    scanner.menu()