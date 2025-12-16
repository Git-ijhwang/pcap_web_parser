use std::process;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use pcap::{Capture, Packet};

use crate::ip::{ipv4::*, port::*, ipv6::*};
use crate::l4::{tcp::*, udp::*, icmp::*};
use crate::gtp::{gtp::*, gtp_ie::*};
use crate::types::*;

use std::time::Instant;

const NEXT_HDR_IPV4: usize = 0x0800;
const NEXT_HDR_IPV6: usize = 0x86dd;

fn format_timestamp(packet: &Packet) -> String
{
    let sec = packet.header.ts.tv_sec as i64;
    let usec = packet.header.ts.tv_usec as u32; // microseconds

    // Create naive datetime from seconds + microseconds
    let naive = NaiveDateTime::from_timestamp_opt(sec, usec * 1000)
        .unwrap_or_else(|| NaiveDateTime::from_timestamp_opt(sec, 0).unwrap());

    let dt: DateTime<Local> = Local.from_local_datetime(&naive).unwrap();

    dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}


fn parse_ethernet(data: &[u8]) -> usize
{
    // let mut ethertype_str = String::from("N/A");
    let mut offset = 0;

    let src_mac = format!("Src Mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
    data[offset+0], data[offset+1], data[offset+2],
    data[offset+3], data[offset+4], data[offset+5]);

    offset += 6;

    let dst_mac = format!("Dst Mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ",
    data[offset+0], data[offset+1], data[offset+2],
    data[offset+3], data[offset+4], data[offset+5]);

    offset += 6;

    let next_type = u16::from_be_bytes([data[offset], data[offset+1]]) as usize;
    // println!("\tMAC:\n\t\t{}\n\t\t{}", src_mac, dst_mac );

    next_type
}

fn print_timestamp(idx:usize, packet: &Packet)
    -> String
{
    let ts = format_timestamp(packet);
    // println!( "[{:05}] {}\tlen:{}", idx, ts, packet.header.len );
    format!( "{}",ts).to_string()
}


async fn parse_l3( next_type: usize, ip_hdr: &[u8],
    parsed_packet: &mut PacketDetail)
-> (usize, usize)
{
    let mut ip= IpInfo::new();
    let mut ip6= Ip6Info::new();

    match next_type {
        PROTO_TYPE_IPINIP | NEXT_HDR_IPV4 => {
            let next_hdr_type = parse_ipv4(
                ip_hdr, &mut ip);
            parsed_packet.l3.push(Layer3Info::IP(ip));
            (next_hdr_type, IP_HDR_LEN)
        },

        NEXT_HDR_IPV6 => {
            let next_hdr_type = parse_ipv6(
                ip_hdr, &mut ip6);
            parsed_packet.l3.push(Layer3Info::IP6(ip6));
            (next_hdr_type, IP6_HDR_LEN)
        },

        _ =>  (0,0)
    }
}


async fn parse_l4( next_type: usize, data_buf: &[u8],
    parsed_packet: &mut PacketDetail)
-> (u16, usize)
{
    match next_type {
        PROTO_TYPE_TCP =>  {
            let mut tcp = TcpInfo::new();
            let result= parse_single_tcp( data_buf , &mut tcp);

            parsed_packet.l4 = Layer4Info::TCP(tcp);
            (result, TCP_HDR_LEN)
        },

        PROTO_TYPE_UDP => {
            let mut udp = UdpInfo::new();
            let result = parse_single_udp( data_buf, &mut udp);

            parsed_packet.l4 = Layer4Info::UDP(udp);
            (result, UDP_HDR_LEN)
        },

        PROTO_TYPE_ICMP => {
            let mut icmp = IcmpInfo::new();
            let result = parse_single_icmp(data_buf, &mut icmp);

            parsed_packet.l4 = Layer4Info::ICMP(icmp);
            (result, ICMP_HDR_LEN)
        },

        _ =>  (0, 0)

    }

}


pub async fn parse_single_packet(path: &PathBuf, id: usize)
-> Result<ParsedDetail, String>
{
    let mut offset: usize = 0;
    let mut cap = Capture::from_file(path)
        .map_err(|e| format!("Failed to open pcap file {}: {}", path.to_string_lossy(), e))?;

    let mut idx: usize = 1;
    let mut parsed_packet = PacketDetail::new();

    let packet = loop {
        match cap.next_packet() {
            Ok(pkt) => {
                if idx == id {
                    break pkt; // 스코프 밖으로 packet 반환
                }
                idx += 1;
            },
            Err(_) => return Err("Packet not found".to_string()),
        }
    };

    // --- Parse Layer 2 Ethernet ---
    let mut next_type = if packet.data.len() >= MIN_ETH_HDR_LEN {
        parse_ethernet(&packet.data)
    } else {
        return Err("Layer 2 parsing faile".to_string());
    };
    offset += MIN_ETH_HDR_LEN;

    // --- Parse Layer 3 (IPv4, IPinIP or IPv6) ---
    loop {
        let (nt, l3_hdr_len) =
            parse_l3(next_type, &packet.data[offset..], &mut parsed_packet).await;

        offset += l3_hdr_len;
        next_type = nt;

        if next_type != PROTO_TYPE_IPINIP {
            break;
        }
    }


    // --- Parse Layer 4 ---
    let (port_number, l4_hdr_len) = parse_l4(next_type, &packet.data[offset..], &mut parsed_packet).await;

    offset += l4_hdr_len;

    // --- Parse Application Layer ---
    if port_number == WELLKNOWN_PORT_GTPV2 {
        let (rest, mut gtpinfo) = parse_gtpc_detail( &packet.data[offset..]).map_err(|e| format!("GTP-C parse error: {:?}", e))?;

        let result = match parse_all_ies(rest) {

            Ok(v) => v,
            Err(_) => {
                // return Err(format!("Parse All failed: {}", e));
                Vec::new()
            }
        };

        gtpinfo.ies = result;
        parsed_packet.app = AppLayerInfo::GTP(gtpinfo);
    }

    Ok(ParsedDetail {
        id,
        packet: parsed_packet
    })
}


pub async fn parse_pcap(path: &Path)
-> Result<ParsedResult, String> 
{
    //read pcap file line by line
    let mut cap = match Capture::from_file(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open pcap file {}: {}", e, path.to_string_lossy());
            process::exit(1);
        }
    };

    let mut idx: usize = 1;
    let mut packets: Vec<PacketSummary> = Vec::new();

    let start = Instant::now(); // 시간 측정 시작

    while let Ok(packet) = cap.next_packet() {

        let mut hdr_len = 0;

        // --- Parse TimeStamp ---
        let mut parsed_packet : PacketSummary = PacketSummary::new();
        parsed_packet.id = idx;
        parsed_packet.ts = print_timestamp(idx, &packet);

        // --- Parse Layer 2 Ethernet ---
        let mut next_type = 0;
        if packet.data.len() >= MIN_ETH_HDR_LEN {
            //get next protocol from Ethernet
            next_type = parse_ethernet(&packet.data);
        }

        hdr_len += MIN_ETH_HDR_LEN;

        // --- Parse Layer 3 ---
        let v= match next_type {
            //IPv4
            NEXT_HDR_IPV4 => {
                Some(parse_ipv4_simple(&packet.data[MIN_ETH_HDR_LEN..], &mut parsed_packet))
            },

            //IPv6
            NEXT_HDR_IPV6 => {
                Some(parse_ipv6_simple(&packet.data[MIN_ETH_HDR_LEN..], &mut parsed_packet))
            }
            _       => None,
        };

        if v.is_none() {
            break;
        }
        next_type = v.unwrap();

        hdr_len += IP_HDR_LEN;

        // --- Parse Layer 4 ---
        let (port_number, l4_hdr_len) =
            match next_type {
                PROTO_TYPE_TCP   => (
                    parse_tcp_simple ( &packet.data[hdr_len..], &mut parsed_packet),
                    TCP_HDR_LEN),
                PROTO_TYPE_UDP   => (
                    parse_udp_simple ( &packet.data[hdr_len..], &mut parsed_packet),
                    UDP_HDR_LEN),
                PROTO_TYPE_ICMP   => (
                    parse_icmp_simple ( &packet.data[hdr_len..], &mut parsed_packet)
                    , ICMP_HDR_LEN),

                _   =>  (0, 0),
            };

        hdr_len += l4_hdr_len;

        // --- Parse Application Layer ---
        match port_number {
            WELLKNOWN_PORT_GTPV2   => {
                parse_gtpc (
                    &packet.data[hdr_len..],
                    &mut parsed_packet)
                    .map_err(|e| format!("GTP-C parse error: {:?}", e))?
            },

            _ => {
                println!("Not GTPv2-C packet");
                (&[] as &[u8], GtpHeader::new())
            },
        };

        packets.push(parsed_packet);

        idx += 1;
    }

    let packet_len = packets.len();
    let duration = start.elapsed(); // 경과 시간 측정
    println!("Parsing took {:?}", duration);

    let result = ParsedResult {
        file: path.to_string_lossy().to_string(),
        total_packets: idx-1,
        packets : packets,
    };

    if packet_len == idx-1 {
        Ok( result )
    }
    else {
        Err("Fail".to_string())
    }
}
