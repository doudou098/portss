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
        
    def menu(self):
        print("Welcome to the Port Scanner!")
        while True:
            print("Please select an option:")
            print("1. Network Discovery")
            print("2. Scan top ports")
            print("3. Targeted Scan")
            print(". Exit")
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
                self.targeted_scan()
            elif choice == '4':
                sys.exit()

            else:
                print("Invalid input, please enter a valid option")

if __name__ == '__main__':
    scanner = PortScanner()
    scanner.menu()

print("4. Targeted Scan")
print("4. Detailed Scan")
choice = ()
if choice == 1:
    pass
elif choice == '3':
    self.targeted_scan()
elif choice == '4':
    self.detailed_scan()
    def targeted_scan(self):
        self.target_ip = input("Enter target IP address to scan: ")
        while True:
            port_str = input("Enter port number(s) to scan (separated by commas): ")
            if not port_str:
                break
            ports = []
            for port in port_str.split(","):
                if not port.isdigit() or not (1 <= int(port) <= 65535):
                    print("Invalid input. Please enter a number between 1 and 65535 or press Enter to finish.")
                    break
                ports.append(int(port))
            else:
                self.target_ports = ports
                break
        
        self.open_ports = []
        self.services = {}
        for port in self.target_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.target_ip, port))
                self.open_ports.append(port)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'unknown'
                self.services[port] = service
            except:
                pass
            finally:
                sock.close()
        if len(self.open_ports) > 0:
            print("Port\tOpen/closed\tService\tVersion")
            for port in self.open_ports:
                print("{}\t{}\t{}\t{}".format(port, 'open', self.services.get(port, 'unknown'), ''))
        else:
            print("No open ports found on {}.".format(self.target_ip))



    def detailed_scan(self):
        self.target_ip = input("Enter the IP address you want to scan: ")
        self.target_port = int(input("Enter the port number you want to scan: "))
        result = self.scanner.scan(self.target_ip, arguments='-sV -p{}'.format(self.target_port))
        try:
            state = result['scan'][self.target_ip]['tcp'][self.target_port]['state']
            name = result['scan'][self.target_ip]['tcp'][self.target_port]['name']
            product = result['scan'][self.target_ip]['tcp'][self.target_port]['product']
            version = result['scan'][self.target_ip]['tcp'][self.target_port]['version']
            print("Port {} is {}".format(self.target_port, state))
            print("Service: {} - {} - {}".format(name, product, version))
        except:
            state = 'unknown'
            name = 'unknown'
            product = 'unknown'
            version = 'unknown'
            print("Port {} is {}, Service: {} {}, Version: {}".format(self.target_port, state, name, product, version))
        choice = input("Do you want to save the results to a file? (y/n): ")
        if choice.lower() == 'y':
            filename = input("Enter the filename to save the results to: ")
            with open(filename, 'w') as f:
                f.write("Port: {}\n".format(self.target_port))
                f.write("State: {}\n".format(state))
                f.write("Name: {}\n".format(name))
                f.write("Product: {}\n".format(product))
                f.write("Version: {}\n".format(version))
                print("Results saved to file: {}".format(filename))
        else:
            print("Results not saved.")

