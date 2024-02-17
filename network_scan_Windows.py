from scapy.all import ARP, Ether, srp
import subprocess
import re

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

    internet_type = input("What is the type of connectivity you are using for the internet? (Wireless|Wired)")

    ip_config_output_raw = subprocess.run(["ipconfig"], capture_output=True)
    ip_config_output = ip_config_output_raw.stdout.decode()
    
    if str(internet_type) == "Wireless":

        connection_type = re.search("Wireless LAN adapter Wi-Fi(.|\n|\r)*", ip_config_output)
        print(connection_type.group())
        connection_type = connection_type.group()
        wireless_ip = re.search("IPv4 Address.*([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])", connection_type)
        print(wireless_ip.group())

    else:

        connection_type = re.search("<>", ip_config_output)
        print(connection_type.group())
        connection_type = connection_type.group()
        wireed_ip = re.search("IPv4 Address.*([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])\.([0-9]|[1-9][0-9]|[1-9][0-9][0-9])", connection_type)
        print(wireed_ip.group())


    #ip = input("enter your local ip appended with //24: ")

    #if int(ip) == -1:
    #    ip = "10.0.0.0/24"

    #target_ip = str(ip)
    
    # scan(target_ip)

    return 0

main()