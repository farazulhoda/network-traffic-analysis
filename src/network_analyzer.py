import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR

def packet_callback(packet):
    global data
    # Extract relevant information from the packet
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6 and TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 17 and UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = None
            dst_port = None

        # Extract DNS information from DNS packets
        if DNS in packet and DNSQR in packet and DNSRR in packet:
            dns_query = packet[DNSQR].qname.decode()
            dns_answer = packet[DNSRR].rdata
        else:
            dns_query = None
            dns_answer = None

        # Append packet information to the DataFrame
        data.append([src_ip, dst_ip, src_port, dst_port, dns_query, dns_answer])

if __name__ == "__main__":
    # Set the network interface to capture traffic from
    INTERFACE = "en0"

    # Set the filter expression to capture specific traffic (optional)
    FILTER = "udp port 53"

    # Start capturing network traffic using scapy
    print("Capturing network traffic on interface", INTERFACE)
    data = []
    sniff(iface=INTERFACE, filter=FILTER, prn=packet_callback, store=False, timeout=30)

    # Convert captured packets to a DataFrame
    columns = ["Source IP", "Destination IP", "Source Port", "Destination Port", "DNS Query", "DNS Answer"]
    df = pd.DataFrame(data, columns=columns)

    # Save the DataFrame to a CSV file
    df.to_csv("analyzed_traffic.csv", index=False)

    # Display the analyzed traffic
    print("Analyzed traffic saved in analyzed_traffic.csv:")
    print(df)