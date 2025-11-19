use crate::types::*;

pub fn parse_icmp_simple (icmp: &[u8], packet: &mut PacketSummary)
-> u16
{
    let mut pos = 0;
    let icmp_type = u8::from_be_bytes([icmp[pos]]);
    // pos + 1;
    // let icmp_code = u8::from_be_bytes([icmp[pos]]);
    // pos + 1;
    // let icmp_checksum = u16::from_be_bytes([icmp[pos], icmp[pos+1]]);
    // pos + 2;

    let mut desc = String::new();
    if icmp_type == 0 {
        desc = "Echo Request".to_string();
    }
    if icmp_type == 8 {
        desc = "Echo Response".to_string();
    }
    packet.src_port = 0;
    packet.dst_port = 0;
    packet.description = desc;

    0
}
/*
 pub id: usize,
    pub ts: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub description: String,
*/