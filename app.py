import sys
from def_ports import NetworkScanner, PortScanner


def main():
    print("Welcome to the CyberTool App!")
    print("[1] Network Discovery")
    print("[2] Scan Targeted IP for Top 10 Ports")
    print("[3] Detailed Scan of a Port")
    choice = input("Please select an option (1/2/3): ")

    if choice == "1":
        network_scanner = NetworkScanner()
        network = input("Enter the network you want to scan (e.g. 192.168.0.0/24): ")
        network_scanner.scan_network(network)
        print("Network Scan complete!")

    elif choice == "2":
        port_scanner = PortScanner()
        ip_address = input("Enter the IP address you want to scan: ")
        port_scanner.scan_top_ports(ip_address)
        print("Top 10 Port Scan complete!")
        port_choice = input("Select a port to learn more about (or enter '0' to exit): ")
        if port_choice != "0":
            port_scanner.scan_port(ip_address, int(port_choice))
            print("Detailed Port Scan complete!")

    elif choice == "3":
        port_scanner = PortScanner()
        ip_address = input("Enter the IP address you want to scan: ")
        port = int(input("Enter the port number you want to scan: "))
        port_scanner.scan_port(ip_address, port)
        print("Detailed Port Scan complete!")

    else:
        print("Invalid choice, please try again.")
        sys.exit(1)


if __name__ == "__main__":
    main()