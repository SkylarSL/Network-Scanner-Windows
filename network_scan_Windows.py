from scapy.all import ARP, Ether, srp

# Function to scan the local network with specified IP subnet
def scan(target_ip) -> None:

    arp = ARP(pdst=target_ip)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Layer the ethernet and arp packet
    packets = ether/arp

    # Now a list of pairs that is formatted (sent_packet, received_packet)
    result = srp(packets, timeout = 3)[0]

    clients = []

    for sent, received in result:

        print(received[1].psrc, received[1].hwsrc)
        
        clients.append({"ip": received.psrc, "mac": received.hwsrc})

    print("target ip was: {}".format(target_ip))

    print("Available devices in the network:")

    print("IP" + " "*20 + "MAC")

    for client in clients:

        print("{:17}    |{}".format(client["ip"], client["mac"]))


def main():

    ip = input("enter your local ip appended with //24: ")

    if int(ip) == -1:
        ip = "10.0.0.0/24"

    target_ip = str(ip)
    
    scan(target_ip)

    return 0

main()