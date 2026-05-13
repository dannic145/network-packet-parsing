from scapy.all import rdpcap, IP, TCP

PCAP_FILE = "http.pcap"

def parse_pcap(file_path):
    packets = rdpcap(file_path)

    total_packets = 0
    ip_packets = 0
    http_packets = 0

    print("\n--- Packet Details ---\n")

    for i, pkt in enumerate(packets, start=1):
        total_packets += 1

        if pkt.haslayer(IP):
            ip_packets += 1

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            print(f"Packet #{i}")
            print(f"  Source IP      : {src_ip}")
            print(f"  Destination IP : {dst_ip}")

            # Check if TCP and HTTP (Port 80)
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport

                if sport == 80 or dport == 80:
                    http_packets += 1
                    print(f"  Protocol       : HTTP (Port 80)")
                else:
                    print(f"  Protocol       : TCP (Non-HTTP)")
            else:
                print(f"  Protocol       : Non-TCP")

            print("-" * 50)

    print("\n--- Summary ---")
    print(f"Total packets captured : {total_packets}")
    print(f"Total IP packets       : {ip_packets}")
    print(f"Total HTTP packets     : {http_packets}")


if __name__ == "__main__":
    try:
        parse_pcap(PCAP_FILE)
    except FileNotFoundError:
        print(f"Error: '{PCAP_FILE}' not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")