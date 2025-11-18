use crate::ip::port::*;
use crate::types::*;

pub fn parse_icmp_simple (icmp: &[u8], packet: &mut PacketSummary)
{
    let mut pos =0;
    let icmp_type = u8::from_be_byte(icmp[pos]);
    pos + 1;
    let icmp_code = u8::from_be_byte(icmp[pos]);
    pos + 1;
    let icmp_checksum = u16::from_be_byte(icmp[pos], icmp[pos+1]);
    pos + 2;
}