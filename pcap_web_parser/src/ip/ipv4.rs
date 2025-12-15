use std::net::Ipv4Addr;
use crate::ip::port::*;
use crate::types::*;

pub fn parse_ipv4_simple(ip_hdr: &[u8], packet: &mut PacketSummary) -> usize
{
    let mut offset: usize = 0;

    offset += 2; //IHL(1byte) + Service Field(1byte)

    offset += 2; //Total Length (2bytes)

    offset += 2; //ID Field (2 bytes)

    offset += 2; //Fragment flag and offset (2bytes)

    offset += 1; //Time to Live (1byte)

    let next_hdr = ip_hdr[offset] as usize;
    // let mut str_proto = String::new();
    if let Some(v) = protocol_to_str(next_hdr) {
        packet.protocol.push_str(&v);
        // str_proto = v;
    }
    else {
        eprintln!("Unknown protocol type {}", next_hdr);
    }
    // packet.protocol.push(str_proto);

    offset += 1; //Next Protocol (1byte)

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

    packet.src_ip.push_str(&src_addr.to_string());
    packet.dst_ip.push_str(&dst_addr.to_string());

    next_hdr
}


pub fn parse_ipv4( ip_hdr: &[u8], ip: &mut IpInfo) -> usize
{
    let mut offset: usize = 0;

    let version_ihl = ip_hdr[offset];
    let version = (version_ihl & 0xf0)>>4;
    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl != IP_HDR_LEN {
        return 0;
    }

    ip.raw.extend_from_slice(&ip_hdr[0..ihl]);
    offset += 1; //IHL(1byte) + Service Field(1byte)

    let service = ip_hdr[offset];
    let dscp:u8 = (service & 0xfc)>>2;
    let ecn:u8 = service & 0x03;
    offset += 1; //IHL(1byte) + Service Field(1byte)

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

    let next_hdr = ip_hdr[offset] as usize;
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


    ip.version = version;
    ip.ihl = ihl as u8;
    ip.dscp = dscp;
    ip.ecn = ecn;
    ip.total_length = total_len;
    ip.id = id;
    ip.flags = frag_flag;
    ip.fragment_offset = frag_offset;
    ip.ttl = ttl;
    ip.checksum = hdr_chk;
    ip.protocol = next_hdr as u8;
    ip.src_addr.push_str(&src_addr.to_string());
    ip.dst_addr.push_str(&dst_addr.to_string());
    ip.next.push_str(&str_proto.to_string());

    next_hdr
}