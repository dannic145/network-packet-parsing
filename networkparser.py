def parse_pcap(filename):
    with open(filename, "rb") as f:
        

        global_header = f.read(24)
        if len(global_header) < 24:
            print("Invalid pcap file.")
            return
        
        print("Global header read successfully.\n")
        
        packet_count = 0
 
        while True:
            packet_header = f.read(16)
            
            if len(packet_header) < 16:
                break 
            
            incl_len = int.from_bytes(packet_header[8:12], byteorder='little')
            packet_data = f.read(incl_len)
            
            if len(packet_data) < 14:
                continue
            
            
            eth_type = int.from_bytes(packet_data[12:14], byteorder='big')
            
            if eth_type != 0x0800:
                continue
            
        
            ip_header_start = 14
            
            src_ip_bytes = packet_data[ip_header_start + 12 : ip_header_start + 16]
            
            dst_ip_bytes = packet_data[ip_header_start + 16 : ip_header_start + 20]
            
            src_ip = ".".join(str(b) for b in src_ip_bytes)
            dst_ip = ".".join(str(b) for b in dst_ip_bytes)
            
            packet_count += 1
            
            print(f"Packet {packet_count}:")
            print(f"Source IP      : {src_ip}")
            print(f"Destination IP : {dst_ip}")
            print("-" * 40)
        
        print(f"\nTotal packets parsed: {packet_count}")


parse_pcap("slammer.pcap")
