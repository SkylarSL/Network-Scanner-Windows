from scapy.all import ARP, Ether, srp
import subprocess
import re

# Function to scan the local network with specified IP subnet
def scan(subnet_addr) -> None:

    # Make an ARP packet with the subnet IP range
    arp = ARP(pdst=subnet_addr)

    # Make an Ethernet packet with broadcast MAC to be sent to all hosts in local network
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Layer the ethernet and arp packet
    packets = ether/arp

    # Now a list of pairs that is formatted (sent_packet, received_packet)
    result = srp(packets, timeout = 3)[0]

    # Initial array for clients
    clients = []

    # Add recieved items to a list
    for sent, received in result:
        # print(received[1].psrc, received[1].hwsrc)
        clients.append({"ip": received.psrc, "mac": received.hwsrc})

    print("target subnet was: {}".format(subnet_addr))

    print("Available devices in the network:")

    print("IP" + " "*20 + "MAC")

    for client in clients:

        print("{:17}    |{}".format(client["ip"], client["mac"]))

def main():

    internet_type = input("What is the type of connectivity you are using for the internet? (Wireless|Wired)")

    ip_config_output_raw = subprocess.run(["ipconfig"], capture_output=True)
    ip_config_output = ip_config_output_raw.stdout.decode()

    subnet_addr = ""
    
    if str(internet_type) == "Wireless":

        # Get the Wireless LAN adapter information
        connection_type = re.search("Wireless LAN adapter Wi-Fi(.|\n|\r)*", ip_config_output)
        connection_type = connection_type.group()
        # Get the IPv4 address associated with the Wireless LAN adapter
        wireless_ip = re.search("IPv4 Address.*([1-9][0-9][0-9]|[1-9][0-9]|[0-9])\.([1-9][0-9][0-9]|[1-9][0-9]|[0-9])\.([1-9][0-9][0-9]|[1-9][0-9]|[0-9])\.([1-9][0-9][0-9]|[1-9][0-9]|[0-9])", connection_type)
        wireless_ip = wireless_ip.group()
        # Get the IP address
        ip_addr = re.search("([1-9][0-9][0-9]|[1-9][0-9]|[0-9])\.([1-9][0-9][0-9]|[1-9][0-9]|[0-9])\.([1-9][0-9][0-9]|[1-9][0-9]|[0-9])\.([1-9][0-9][0-9]|[1-9][0-9]|[0-9])", wireless_ip)
        ip_addr = ip_addr.group()

        # Turn found IP address into likely subnet address
        ip_addr = ip_addr.split(".")
        ip_addr[-1] = "0/24"
        subnet_addr = ".".join(ip_addr)

    elif str(internet_type) == "Wired":

        # TBD
        """
        connection_type = re.search("<>", ip_config_output)
        print(connection_type.group())
        connection_type = connection_type.group()
        wired_ip = re.search("IPv4 Address.*([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])", connection_type)
        print(wired_ip.group())
        wired_ip = wired_ip.group()
        # Get the IP address
        ip_addr = re.search("([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])", wired_ip)
        """

        subnet_addr  = -1

    else:

        subnet_addr  = -1

    # Error checking
    if subnet_addr  == -1:
        print("No Subnet found.")

    # Run scan
    scan(subnet_addr )

    return 0

main()