
import socket
import subprocess
import sys

import nmap


class PortScanner:
    def __init__(self):
        self.target_ip = ''
        self.target_ports = []
        self.open_ports = []
        self.services = {}
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

    def top_ports(self, ip_address):
        top_ports = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        open_ports = []
        closed_ports = []
        for port in top_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)
            sock.close()
        print("Open ports on %s:" % ip_address)
        for port in open_ports:
            service = self.get_service_name(port)
            print("  %s (%s) open" % (port, service))
        for port in closed_ports:
            service = self.get_service_name(port)
            print("  %s (%s) closed" % (port, service))
        while True:
            port_input = input("Enter a port number to see its version or press Enter to go back to the main menu: ")
            if port_input == "":
                break
            try:
                port = int(port_input)
                if port in open_ports:
                    version = self.get_service_version(ip_address, port)
                    service = self.get_service_name(port)
                    if version:
                        print("Version of %s (%s) on %s: %s" % (port, service, ip_address, version))
                    else:
                        print("Version of %s (%s) on %s: Unknown" % (port, service, ip_address))
                elif port in closed_ports:
                    print("Port %s is closed" % port)
                else:
                    print("Port %s is not in the list of open or closed ports" % port)
            except ValueError:
                print("Invalid input, please enter a valid port number")

    def get_service_name(self, port):
        try:
            services = socket.getservbyport(port)
            return services
        except OSError:
            return "Unknown"

    def get_service_version(self, ip_address, port):
        try:
            self.scanner.scan(ip_address, str(port))
            return self.scanner[ip_address]['tcp'][port]['product'] + " " + self.scanner[ip_address]['tcp'][port]['version']
        except KeyError:
            return "Unknown"
        
    def scan_all_ports(self, ip_address):
        open_ports = []
        scanner = nmap.PortScanner()
        scanner.scan(ip_address, arguments='-p-')
        for port in scanner[ip_address]['tcp']:
            if scanner[ip_address]['tcp'][port]['state'] == 'open':
                service_name = socket.getservbyport(port)
                try:
                    service_version = scanner[ip_address]['tcp'][port]['product'] + " " + scanner[ip_address]['tcp'][port]['version']
                except KeyError:
                    service_version = "Unknown"
                open_ports.append((port, service_name, service_version))
        if open_ports:
            print("Open ports on {}: ".format(ip_address))
            for port, service_name, service_version in open_ports:
                print("Port {} ({}) is open, running {}".format(port, service_name, service_version))
        else:
            print("No open ports found on {}".format(ip_address))


    def scan_vulnerabilities(self, ip_address, port):
        scanner = nmap.PortScanner()
        scanner.scan(ip_address, str(port), arguments='-sV -sC')
        script_output = scanner[ip_address]['tcp'][port]['script']
        if 'vulners' in script_output:
            vulnerabilities = script_output['vulners']
            print(f"Vulnerabilities found on port {port} of {ip_address}:")
            for vulnerability in vulnerabilities:
                print(f"\t- {vulnerability}")
        else:
            print(f"No vulnerabilities found on port {port} of {ip_address}")
 
    def targeted_scan(self, port):
        ip_address = input("Enter the IP address to scan: ")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            service_name = self.get_service_name(port)
            print("Port {} ({}) is open on {}".format(port, service_name, ip_address))
            details = input("Would you like to display more details about the service running on this port? (y/n) ")
            if details.lower() == "y":
                service_version = self.get_service_version(ip_address, port)
                print("Version of {} on {}: {}".format(service_name, ip_address, service_version))
            return True
        else:
            print("Port {} is closed on {}".format(port, ip_address))  
            return False
            
    def menu(self):
        print("Welcome to the Port Scanner!")
        while True:
            print("Please select an option:")
            print("1. Network Discovery")
            #will list all active devices on the network
            print("2. Scan top ports")
            #will scan top ports and will display open and say what service is running and ask user if he want to see more details if yes will print version running on choosen port otherwice will display menu
            print("3. Targeted Scan")
            #will scan inputed ip for inputed port user will have option to see more (eg service running on and vulnerabilities)
            print("4. Scan all ports")
            #will scan all tcp ports and display open 
            print("5. Vulnerability scan")
            # will display all open port and say what service is on and will display vulnerabilities            
            print("6. Exit")
            choice = input()

            if choice == '1':
                ip_list = self.network_discovery()
                print("Scanning the following IP addresses:")
                for ip in ip_list:
                    print(ip)
                self.scanner.scan(hosts=' '.join(ip_list), arguments='-n -sP')
                hosts_list = [(x, self.scanner[x]['status']['state']) for x in self.scanner.all_hosts()]
                print("Active devices:")
                for host, status in hosts_list:
                    if status == 'up':
                        print(host)

            elif choice == '2':
                ip_address = input("Enter the IP address to scan: ")
                self.top_ports(ip_address)

            elif choice == '3':
                port = int(input("Enter the port number: "))
                is_open = self.targeted_scan(port, ip_address)
                if is_open:
                    while True:
                        option = input("Do you want to see more details? (y/n): ")
                        if option.lower() == "y":
                            print("More details about port {}...".format(port))

                        elif option.lower() == "n":
                            break
                        else:
                            print("Invalid input, please enter y or n")
            elif choice == '4':
                ip_address = input("Enter the IP address to scan: ")
                open_ports = self.scan_all_ports(ip_address)
                if open_ports:
                    for port, service in open_ports.items():
                        print("Port {} ({}) is open on {}".format(port, service, ip_address))
                        details = input("Would you like to display more details abo4ut the service running on this port? (y/n) ")
                        if details.lower() == "y":
                            try:
                                version = self.get_service_version(ip_address, port)
                                print("Version of {} on {}: {}".format(service, ip_address, version))
                            except KeyError:
                                print("Version of {} on {}: Unknown".format(service, ip_address))
            elif choice == '5':
                ip_address = input("Enter the IP address to scan: ")
                self.vuln_scan(ip_address)

            elif choice == '6':
                sys.exit()

            else:
                print("Invalid input, please enter a valid option")

if __name__ == '__main__':
    scanner = PortScanner()
    scanner.menu()