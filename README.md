# 🔬 Network Packet Parsing

A collection of exercises exploring raw network packet analysis — from byte-level binary parsing to protocol-aware dissection of HTTP and TLS 1.2 traffic using Python.

---

## Repository Structure

```
.
├── slammer.pcap          # PCAP capture of the SQL Slammer worm
├── http.pcap             # PCAP capture of HTTP traffic
├── tls1_2.pcap           # PCAP capture of a TLS 1.2 handshake
│
├── networkparser.py      # Exercise 1 – Raw byte parsing (Slammer)
├── parsehttp.py          # Exercise 2 – HTTP packet parsing (Scapy)
└── tls_1_2_parse.py      # Exercise 3 – TLS 1.2 handshake parsing (Scapy)
```

---

## Exercises

### 1. Parsing a Network Packet (Slammer Worm)

**File:** `networkparser.py`  
**PCAP:** `slammer.pcap`

The goal of this exercise is to understand low-level packet structure by parsing a PCAP file **byte by byte**, without any external parsing library.

The script manually reads the PCAP global header, iterates over each packet record, extracts the Ethernet frame type, and reads the source and destination IP addresses directly from the IPv4 header offsets.

**What it does:**
- Reads raw binary PCAP format (global header + per-packet records)
- Filters for IPv4 packets (EtherType `0x0800`)
- Extracts and prints source and destination IP addresses
- Reports total packet count

**Run it:**
```bash
python networkparser.py
```

> The [SQL Slammer worm](https://en.wikipedia.org/wiki/SQL_Slammer) (2003) was a fast-spreading worm that exploited a buffer overflow in Microsoft SQL Server, causing widespread internet disruption through a flood of UDP packets.

---

### 2. Parsing an HTTP Packet

**File:** `parsehttp.py`  
**PCAP:** `http.pcap`

The goal of this exercise is to understand the HTTP protocol by analysing real captured traffic.

The script uses [Scapy](https://scapy.net/) to load and dissect packets, identifying TCP flows on port 80 as HTTP traffic.

**What it does:**
- Loads all packets from the PCAP using Scapy
- Identifies IP packets and extracts source/destination addresses
- Detects HTTP traffic by checking for TCP port 80
- Prints a per-packet summary and a final count breakdown

**Run it:**
```bash
python parsehttp.py
```

**Output includes:**
- Source and destination IP per packet
- Protocol classification (HTTP / TCP / Non-TCP)
- Total packet count, IP packet count, and HTTP packet count

---

### 3. Parsing a TLS 1.2 Handshake

**File:** `tls_1_2_parse.py`  
**PCAP:** `tls1_2.pcap`

The goal of this exercise is to understand the TLS handshake process by inspecting the raw bytes of a TLS 1.2 session.

The script uses Scapy to read TCP payloads and manually inspects the TLS record layer bytes to identify handshake message types.

**What it does:**
- Identifies TLS records by checking for Content Type `0x16` (Handshake)
- Reads the TLS version field from the record header
- Identifies handshake message types:
  - `1` → **Client Hello**
  - `2` → **Server Hello**
  - Other → Generic TLS Handshake
- Summarises Client Hello and Server Hello counts

**Run it:**
```bash
python tls_1_2_parse.py
```

**TLS Handshake byte layout inspected:**

| Byte(s) | Field            |
|---------|------------------|
| 0       | Content Type (22 = Handshake) |
| 1–2     | TLS Version      |
| 3–4     | Record Length    |
| 5       | Handshake Type   |

---

## Requirements

### Python version
Python 3.7+

### Dependencies

Exercises 2 and 3 require [Scapy](https://scapy.net/). Exercise 1 has **no dependencies** — it uses only the Python standard library.

Install Scapy via pip:
```bash
pip install scapy
```

---

## Getting Started

```bash
# Clone the repo
git clone https://github.com/dannic145e/network-packet-parsing.git
cd network-packet-parsing

# Install dependencies
pip install scapy

# Run each exercise
python networkparser.py
python parsehttp.py
python tls_1_2_parse.py
```

> **Note:** On some systems, Scapy may require elevated privileges (e.g. `sudo`) to read raw network data. For these exercises, reading from PCAP files should work without root.

---

## References

1. PCAP sample files sourced from public packet capture repositories
2. [SQL Slammer Worm – Wikipedia](https://en.wikipedia.org/wiki/SQL_Slammer)
3. [Scapy Documentation](https://scapy.readthedocs.io/)
4. [TLS 1.2 RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246)
5. [PCAP File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
