use crate::ip::port::*;
use crate::types::*;

pub fn parse_tcp_simple(tcp: &[u8], packet: & mut PacketSummary) -> u16
{
    if tcp.len() < 20 {
        println!( "TCP header too short");
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);

    packet.src_port = src_port;
    packet.dst_port = dst_port;

    dst_port
}

pub fn parse_single_tcp(tcp_buf: &[u8], tcp: & mut TcpInfo) -> u16
{
    if tcp_buf.len() < 20 {
        println!( "TCP header too short");
    }

    let src_port = u16::from_be_bytes([tcp_buf[0], tcp_buf[1]]);
    let dst_port = u16::from_be_bytes([tcp_buf[2], tcp_buf[3]]);

    let seq_num = u32::from_be_bytes([tcp_buf[4], tcp_buf[5], tcp_buf[6], tcp_buf[7]]);
    let ack_num = u32::from_be_bytes([tcp_buf[8], tcp_buf[9], tcp_buf[10], tcp_buf[11]]);

    let data_offset = (tcp_buf[12] >> 4) * 4;
    let flags = tcp_buf[13];

    // let syn = (flags & 0x02) != 0;
    // let ack = (flags & 0x10) != 0;
    // let fin = (flags & 0x01) != 0;
    // let rst = (flags & 0x04) != 0;

    let win_size = u16::from_be_bytes([tcp_buf[14], tcp_buf[15]]);
    let chksum   = u16::from_be_bytes([tcp_buf[16], tcp_buf[17]]);

    let mut str_src_port = String::new();
    if let Some(v) = port_to_str(src_port) {
        str_src_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", src_port);
    }

    let mut str_dst_port = "".to_string();
    if let Some(v) = port_to_str(dst_port) {
        str_dst_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", dst_port);
    }

    tcp.src_port        = src_port;
    tcp.src_port_str    = str_src_port;
    tcp.dst_port        = dst_port;
    tcp.dst_port_str    = str_dst_port;
    tcp.seq             = seq_num;
    tcp.ack             = ack_num;
    tcp.flags           = flags;
    tcp.window          = win_size;
    tcp.header_sz       = data_offset;
    tcp.checksum        = chksum;
    tcp.urgent          = 0;
    tcp.raw.extend_from_slice(&tcp_buf[0..20]);
    tcp.payload = Some((tcp_buf[20..]).to_vec());
        
    dst_port
}