# Telecom Packet Analyzer for 3GPP Mobile Core Networks
This project is a web-based mobile core network protocol analyzer built with Rust and React.

It is designed to parse, decode, and visualize 3GPP control-plane protocols such as GTPv2-C and PFCP, providing an intuitive interface for packet inspection, Information Element (IE) decoding, protocol tree visualization, and hex dump analysis.

In addition to telecom protocols, the analyzer also supports common network protocol layers, including IPv4, TCP, UDP, and ICMP.

## Videos

- This video demonstrates how to load a PCAP file and visualize the dynamic call flow of GTPv2-C packets step by step.

  https://github.com/user-attachments/assets/b864f371-f4ce-46cb-942f-dfc50dcb6989

---

- This video illustrates the GTP call flow while dynamically showing the bearer status of each node throughout the entire session lifecycle, from session establishment to termination.

  https://github.com/user-attachments/assets/a97a044f-c344-46ab-adf1-02daf5eec640

# Screenshots


- Packet List
![image](https://github.com/user-attachments/assets/8b8f5858-a2f6-4673-b675-fb2d8e7fe84d)


---

- Packet Detail
![image](https://github.com/user-attachments/assets/4158770c-acd7-4a7c-b8a4-c1231852375a)
---

- GTPv2-C Detail
![image](https://github.com/user-attachments/assets/bb6d618c-7791-4b11-bb74-6c2c487c7cf9)

---

- GTPv2-C HexDump
![image](https://github.com/user-attachments/assets/b54ee5fe-831c-4c71-8584-fa6dfd928fc4)

---

- PFCP Packet Detail
![image](https://github.com/user-attachments/assets/bf043330-89c1-4deb-aaad-7dba24284dcb)

---

## Features
- **Basic Protocols(IPv4, IPv6, ICMP, UDP, and TCP)**
- **GTPv2-C Basic Header and Information Elements (IE)**
- **BearerTFT & Packet Filter Parsing**
- **GTPv2 Bearer status Visualizer for each GTP Nodes**
- **PFCP**
- **Hex dump rendering and frontend visualization**

The parser reads raw packet data and produces structured JSON output, which can be visualized in a frontend.

---

### Frontend (React)
- Displays parsed structures
- Hex dump viewer
- Collapsible protocol sections
- Packet Filter & BearerTFT rendering

---

## How to Build
### Rust backend
- cd parser
- cargo build
- cargo run

### Frontend
- cd visualizer
- npm install
- npm start
