use crate::ip::port::*;
use crate::types::*;


pub fn parse_tcp_simple(tcp: &[u8], packet: & mut PacketSummary) -> u16
{
    if tcp.len() < 20 {
        println!( "TCP header too short");
    }

    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);

    // let seq_num = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    // let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);

    // let data_offset = (tcp[12] >> 4) * 4;
    // let flags = tcp[13];

    // let syn = (flags & 0x02) != 0;
    // let ack = (flags & 0x10) != 0;
    // let fin = (flags & 0x01) != 0;
    // let rst = (flags & 0x04) != 0;

    // let win_size = u16::from_be_bytes([tcp[14], tcp[15]]);
    // let chksum   = u16::from_be_bytes([tcp[16], tcp[17]]);

    let mut str_src_port = "".to_string();
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

    // println!(
    //     "\tSrc:{}[{}]\tDst:{}[{}]\tSeq:{}, Ack:{}, Win:{}, ChkSum:0x{:04x} Flags:[{}{}{}{}]",
    //     src_port, str_src_port, dst_port, str_dst_port,
    //     seq_num, ack_num, win_size, chksum,
    //     if syn{"SYN "} else {""},
    //     if ack{"ACK "} else {""},
    //     if fin{"FIN "} else {""},
    //     if rst{"RST "} else {""},
    // );
    packet.src_port = src_port;
    packet.dst_port = dst_port;

    dst_port
}

// pub fn parse_tcp(tcp: &[u8], packet: & mut PacketDetail) -> u16
pub fn parse_tcp(tcp_buf: &[u8], tcp: & mut TcpInfo) -> u16
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

    let syn = (flags & 0x02) != 0;
    let ack = (flags & 0x10) != 0;
    let fin = (flags & 0x01) != 0;
    let rst = (flags & 0x04) != 0;

    let win_size = u16::from_be_bytes([tcp_buf[14], tcp_buf[15]]);
    let chksum   = u16::from_be_bytes([tcp_buf[16], tcp_buf[17]]);

    let mut str_src_port = "".to_string();
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

    println!(
        "\tSrc:{}[{}]\tDst:{}[{}]\tSeq:{}, Ack:{}, Win:{}, ChkSum:0x{:04x} Flags:[{}{}{}{}]",
        src_port, str_src_port, dst_port, str_dst_port,
        seq_num, ack_num, win_size, chksum,
        if syn{"SYN "} else {""},
        if ack{"ACK "} else {""},
        if fin{"FIN "} else {""},
        if rst{"RST "} else {""},
    );

    // tcp = Layer4Info::TCP( TcpInfo {
        tcp.src_port = src_port;
        tcp.dst_port = dst_port;
        tcp.seq = seq_num;
        tcp.ack = ack_num;
        tcp.flags = flags;
        tcp.window = win_size;
        tcp.header_sz = data_offset;
        tcp.checksum = chksum;
        tcp.urgent = 0;
    // });
        
    // packet.l4.tcp.get_or_insert( TcpInfo {
    //     seq: 0,
    //     src_port: 0,
    //     dst_port: 0,
    // });
    // tcp.seq = seq_num;
    // tcp.src_port = src_port;
    // tcp.dst_port = dst_port;

    dst_port
}

fn parse_udp_simple (udp: &[u8], packet: & mut PacketSummary) -> u16
{
    let mut pos = 0;

    let src_port = u16::from_be_bytes([udp[pos], udp[pos+1]]);
    // let str_src_port = port_to_str(src_port);
    let mut str_src_port = "".to_string();
    if let Some(v) = port_to_str(src_port) {
        str_src_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", src_port);
    }

    pos += 2;

    let dst_port = u16::from_be_bytes([udp[pos], udp[pos+1]]);
    // let str_dst_port = port_to_str(dst_port);
    let mut str_dst_port = "".to_string();
    if let Some(v) = port_to_str(dst_port) {
        str_dst_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", dst_port);
    }

    pos += 2;

    // let seq = u32::from_be_bytes([
    //     udp[pos], udp[pos+1],
    //     udp[pos+2], udp[pos+3],
    //     ]);
    // pos += 4;

    // let act = u32::from_be_bytes([
    //     udp[pos], udp[pos+1],
    //     udp[pos+2], udp[pos+3],
    //     ]);
    // pos += 4;

    // let hdr_sz = u8::from_be_bytes(byte)

    // let chksum = u16::from_be_bytes([udp[pos], udp[pos+1]]);

    // let print = format!("\tUDP:\n\t\tSrc:{}[{}]\n\t\tDst:{}[{}]\n\t\tLen:{}\n\t\tChkSum:0x{:04x}",
        // src_port, str_src_port, dst_port, str_dst_port, len, chksum);

    // println!("{}", print);

    packet.src_port = src_port;
    packet.dst_port = dst_port;

    dst_port
}

pub fn parse_udp(udp_buf: &[u8], udp: & mut UdpInfo) -> u16
{
    let mut pos = 0;

    let src_port = u16::from_be_bytes([udp_buf[pos], udp_buf[pos+1]]);
    // let str_src_port = port_to_str(src_port);
    let mut str_src_port = String::new();
    if let Some(v) = port_to_str(src_port) {
        str_src_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", src_port);
    }

    pos += 2;

    let dst_port = u16::from_be_bytes([udp_buf[pos], udp_buf[pos+1]]);
    // let str_dst_port = port_to_str(dst_port);
    let mut str_dst_port = String::new();
    if let Some(v) = port_to_str(dst_port) {
        str_dst_port = v;
    }
    else {
        eprintln!("Unknown protocol type {}", dst_port);
    }

    pos += 2;

    let len = u16::from_be_bytes([udp_buf[pos], udp_buf[pos+1]]);
    pos += 2;

    let chksum = u16::from_be_bytes([udp_buf[pos], udp_buf[pos+1]]);

    udp.raw.extend_from_slice(&udp_buf[0..8]);

    let print = format!("\tUDP:\n\t\tSrc:{}[{}]\n\t\tDst:{}[{}]\n\t\tLen:{}\n\t\tChkSum:0x{:04x}",
        src_port, str_src_port, dst_port, str_dst_port, len, chksum);

    println!("{}", print);

    // if let Layer4Info::UDP(udp) = &mut packet.l4 {
    // let udp = packet.udp.get_or_insert( UdpInfo {
    //     src_port: 0,
    //     dst_port: 0,
    // });
        udp.src_port = src_port;
        udp.dst_port = dst_port;
        udp.length = len;
        udp.checksum = chksum;
    // }

    dst_port
}

pub fn preparse_layer4(proto_num:usize, l4: &[u8], packet: & mut PacketSummary, detail: bool) -> (u16, usize)
{
    let proto= protocol_to_str(proto_num);

    packet.protocol = proto.unwrap();

    match proto_num {
        6   =>  return (parse_tcp_simple(l4, packet), 20),
        17  => return (parse_udp_simple(l4, packet), 8),
        // 1   => println!("ICMP"),
        _   => {
            println!("IP proto {}", proto_num);
            return (0, 0);
        }
    }
}

// pub fn preparse_layer4_detail(proto_num:usize, l4: &[u8], packet: & mut PacketDetail)
// // -> Result<(u16, usize), u32>
// -> (u16, usize)
// {
//     let proto= protocol_to_str(proto_num);

//     // packet.protocol = proto.unwrap();

//     match proto_num {
//         6   =>  {
//             packet.l4 = Layer4Info::TCP(TcpInfo::new());
//             (parse_tcp(l4, packet), 20)
//         },
//         17  => {
//             packet.l4 = Layer4Info::UDP(UdpInfo::new());
//             (parse_udp(l4, packet), 8)
//         },
//         _   => {
//             println!("IP proto {}", proto_num);
//              (0, 0)
//         }
//     }
// }
