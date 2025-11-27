use crate::types::*;

pub fn parse_icmp_simple (icmp: &[u8], packet: &mut PacketSummary)
-> u16
{
    let icmp_type = u8::from_be_bytes([icmp[0]]);

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

pub fn parse_single_icmp(icmp_buf: &[u8], icmp: &mut IcmpInfo)
-> u16
{
    let icmp_type = icmp_buf[0];
    let code = icmp_buf[1];
    let checksum = u16::from_be_bytes([icmp_buf[2], icmp_buf[3]]);

    icmp.icmp_type = icmp_type;
    icmp.code = code;
    icmp.checksum = checksum;

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