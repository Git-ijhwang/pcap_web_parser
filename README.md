# Packet Parsing System (IPv4 / UDP / TCP / ICMP / GTPv2-C)

This project is a packet parsing engine implemented in Rust.  
It supports parsing multiple network protocol layers including:
## ScreenShot

<img width="1140" height="530" alt="image" src="https://github.com/user-attachments/assets/dc9e2c33-5307-491c-b3a8-cc96a4081702" />
<img width="1147" height="408" alt="image" src="https://github.com/user-attachments/assets/c122431a-1f5f-4c04-ae6f-3b250f36858b" />

<img width="1571" height="698" alt="image" src="https://github.com/user-attachments/assets/6870a295-7333-4eeb-9552-e5c756912042" />
<img width="1365" height="735" alt="image" src="https://github.com/user-attachments/assets/b54ee5fe-831c-4c71-8584-fa6dfd928fc4" />

---

## 🚀 Features
- **IPv4**
- **UDP**
- **TCP**
- **ICMP**
- **GTPv1-U / GTPv2-C (partially)**
- **GTPv2-C Information Elements (IE)**
- **BearerTFT & Packet Filter Parsing**
- Hex dump rendering and frontend visualization (React)

The parser reads raw packet data and produces structured JSON output, which can be visualized in a frontend.

---

### ✔ 7. Frontend (React)
- Displays parsed structures
- Hex dump viewer
- Collapsible protocol sections
- Packet Filter & BearerTFT rendering

---

## 📦 How to Build
### Rust backend
- cd pcap_web_parser
- cargo build
- cargo run

### Frontend
- cd pcap-web-frontend
- npm install
- npm start
