use crate::types::*;

pub const ICMP_ECHO_REQ: u8     = 0;
pub const ICMP_ECHO_RSP: u8     = 8;

pub fn parse_icmp_simple (icmp: &[u8], packet: &mut PacketSummary)
-> u16
{
    let icmp_type = u8::from_be_bytes([icmp[0]]);

    let mut desc = String::new();
    if icmp_type == ICMP_ECHO_REQ {
        desc = "Echo Request".to_string();
    }
    else if icmp_type == ICMP_ECHO_RSP {
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
    let mut offset: usize = 0;

    let icmp_type = icmp_buf[offset];
    offset += 1;

    let code = icmp_buf[offset];
    offset += 1;

    let checksum = u16::from_be_bytes([icmp_buf[offset], icmp_buf[offset + 1]]);
    offset += 2;

    let id = u16::from_be_bytes([icmp_buf[offset], icmp_buf[offset + 1]]);
    offset += 2;

    let seq = u16::from_be_bytes([icmp_buf[offset], icmp_buf[offset + 1]]);

    icmp.icmp_type = icmp_type;
    icmp.code = code;
    icmp.checksum = checksum;
    icmp.id = id;
    icmp.seq = seq;
    icmp.raw.extend_from_slice(&icmp_buf);

    0
}
