use std::net::Ipv4Addr;
use crate::port::*;
use crate::parse_pcap::{IP_HDR_LEN, MIN_ETH_HDR_LEN};
use crate::PacketSummary;

pub fn parse_ipv4(ip_hdr: &[u8], packet: &mut PacketSummary) -> usize
{
    let mut next_hdr: usize = 0;
    let mut offset: usize = 0;

    let version_ihl = ip_hdr[offset];
    let version = (version_ihl & 0xf0)>>4;
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl != IP_HDR_LEN {
        return 0;
    }
    offset += 2; //IHL(1byte) + Service Field(1byte)

    let total_len: u16 = u16::from_be_bytes( [
        ip_hdr[offset], ip_hdr[offset+1]
    ]);
    offset += 2; //Total Length (2bytes)

    let id = u16::from_be_bytes([
        ip_hdr[offset], ip_hdr[offset+1]
    ]);
    offset += 2; //ID Field (2 bytes)

    let frag : u16 = u16::from_ne_bytes([
        ip_hdr[offset], ip_hdr[offset+1]
    ]);

    let frag_flag: u8 = ((frag & 0x40)>>5) as u8;
    let mut frag_offset: u16 = 0;
    if frag_flag == 0x02 {
        frag_offset = frag & 0x1f;
    }
    offset += 2; //Fragment flag and offset (2bytes)

    let ttl = ip_hdr[offset];
    offset += 1; //Time to Live (1byte)

    next_hdr = ip_hdr[offset] as usize;
    let mut str_proto = String::new();
    if let Some(v) = protocol_to_str(next_hdr) {
        str_proto = v;
    }
    else {
        eprintln!("Unknown protocol type {}", next_hdr);
    }

    offset += 1; //Next Protocol (1byte)

    let hdr_chk = u16::from_be_bytes([
        ip_hdr[offset], ip_hdr[offset+1]
    ]);
    offset += 2; //Header Checksum Field (2bytes)

    let mut src_addr = Ipv4Addr::new(0,0,0,0);
    if let Ok(octets) = ip_hdr[offset..offset+4].try_into() {
        src_addr = Ipv4Addr::from_octets(octets);
    }
    else {
        eprintln!("Failure to read Src Addr");
    }
    offset += 4;

    let mut dst_addr = Ipv4Addr::new(0,0,0,0);
    if let Ok(octets) = ip_hdr[offset..offset+4].try_into() {
        dst_addr = Ipv4Addr::from_octets(octets);
    }
    else {
        eprintln!("Failure to read Src Addr");
    }

    let mut ip_print = "".to_string();

        ip_print = format!("\tIP:
\t\tVer: {}
\t\tLen: {} bytes
\t\tTotalLen: {} bytes
\t\tID: 0x{:04x}
\t\tF: 0x{:02x}
\t\tTTL: {}
\t\tNext_Proto: {} [{}]
\t\tChkSum: 0x{:04x}
\t\tSrc Addr: {}
\t\tDst Addr: {}",
        version, ihl, total_len, id, frag_flag, ttl, next_hdr, str_proto, hdr_chk, src_addr, dst_addr);
    println!("{}", ip_print);

    packet.src_ip.push_str(&src_addr.to_string());
    packet.dst_ip.push_str(&dst_addr.to_string());

    next_hdr
}