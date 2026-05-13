from scapy.all import rdpcap, IP, TCP

PCAP_FILE = "tls1.2.pcap"

def parse_tls_pcap(file_path):
    packets = rdpcap(file_path)

    total_packets = 0
    tls_packets = 0
    client_hello_count = 0
    server_hello_count = 0

    print("\n--- TLS Packet Details ---\n")

    for i, pkt in enumerate(packets, start=1):
        total_packets += 1

        if pkt.haslayer(IP) and pkt.haslayer(TCP):

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            tcp_payload = bytes(pkt[TCP].payload)

            if len(tcp_payload) > 5:
                if tcp_payload[0] == 22:

                    tls_packets += 1

                    # TLS Version
                    version = tcp_payload[1:3].hex()

                    # Handshake Type
                    handshake_type = tcp_payload[5]

                    print(f"Packet #{i}")
                    print(f"  Source IP      : {src_ip}")
                    print(f"  Destination IP : {dst_ip}")
                    print(f"  TLS Version    : 0x{version}")

                    if handshake_type == 1:
                        client_hello_count += 1
                        print(f"  Handshake Type : Client Hello")

                    elif handshake_type == 2:
                        server_hello_count += 1
                        print(f"  Handshake Type : Server Hello")

                    else:
                        print(f"  Handshake Type : Other TLS Handshake")

                    print("-" * 50)

    print("\n--- Summary ---")
    print(f"Total packets captured : {total_packets}")
    print(f"Total TLS packets      : {tls_packets}")
    print(f"Client Hello packets   : {client_hello_count}")
    print(f"Server Hello packets   : {server_hello_count}")


if __name__ == "__main__":
    try:
        parse_tls_pcap(PCAP_FILE)

    except FileNotFoundError:
        print(f"Error: '{PCAP_FILE}' not found.")

    except Exception as e:
        print(f"Unexpected error: {e}")