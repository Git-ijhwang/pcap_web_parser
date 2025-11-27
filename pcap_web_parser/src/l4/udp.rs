use crate::ip::port::*;
use crate::types::*;

pub fn parse_udp_simple (udp: &[u8], packet: & mut PacketSummary) -> u16
{
    let mut pos = 0;

    let src_port = u16::from_be_bytes([udp[pos], udp[pos+1]]);
    pos += 2;

    let dst_port = u16::from_be_bytes([udp[pos], udp[pos+1]]);
    pos += 2;

    packet.src_port = src_port;
    packet.dst_port = dst_port;

    dst_port
}

pub fn parse_single_udp(udp_buf: &[u8], udp: & mut UdpInfo) -> u16
{
    let mut pos = 0;

    let src_port = u16::from_be_bytes([udp_buf[pos], udp_buf[pos+1]]);
    // let str_src_port = port_to_str(src_port);
    let mut str_src_port = String::new();
    let mut str_dst_port = String::new();

    if let Some(v) = port_to_str(src_port) {
        str_src_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", src_port);
    }

    pos += 2;

    let dst_port = u16::from_be_bytes([udp_buf[pos], udp_buf[pos+1]]);
    pos += 2;

    if let Some(v) = port_to_str(dst_port) {
        str_dst_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", src_port);
    }

    let len = u16::from_be_bytes([udp_buf[pos], udp_buf[pos+1]]);
    pos += 2;

    let chksum = u16::from_be_bytes([udp_buf[pos], udp_buf[pos+1]]);


    udp.src_port = src_port;
    if str_src_port.len() > 0 {
        udp.str_src_port = str_src_port;
    }
    udp.dst_port = dst_port;
    if str_dst_port.len() > 0 {
        udp.str_dst_port = str_dst_port;
    }
    udp.length = len;
    udp.checksum = chksum;
    udp.raw.extend_from_slice(&udp_buf[0..8]);

    dst_port
}
