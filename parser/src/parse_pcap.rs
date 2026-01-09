use std::process;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use pcap::{Capture, Packet};

use crate::ip::{self, ipv4::*, ipv6::*, port::{self, *}};
use crate::l4::{tcp::*, udp::*, icmp::*};
use crate::gtp::{gtp::*, gtp_ie::*};
use crate::pfcp::{pfcp::*, pfcp_ie::*};
use crate::types::*;

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

    // dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
    dt.format("%H:%M:%S%.3f").to_string()
}


fn print_timestamp(idx:usize, packet: &Packet)
    -> String
{
    let ts = format_timestamp(packet);
    format!( "{}",ts).to_string()
}


pub fn parse_ethernet(data: &[u8]) -> usize
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

    next_type
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


async fn parse_l4( next_type: usize,
    data_buf: &[u8],
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

async fn parse_app(port_number: u16,
    data_buf: &[u8],
    parsed_packet: &mut PacketDetail)
{
    match port_number {
        L4_PORT_GTPV2 => {
            let (rest, mut gtpinfo) =
                parse_gtpc_detail(data_buf)
                    .map_err( |e| format!("GTP-C parse error: {:?}", e)).unwrap();

            let result = match parse_all_ies(rest) {

                Ok(v) => v,
                Err(_) => {
                    // return Err(format!("Parse All failed: {}", e));
                    Vec::new()
                }
            };

            gtpinfo.ies = result;
            parsed_packet.app = AppLayerInfo::GTP(gtpinfo);
        },

        L4_PORT_PFCP => {
            let (rest, mut pfcpinfo) =
                parse_pfcp_detail(data_buf)
                    .map_err( |e| format!("PFCP parse error: {:?}", e)).unwrap();

            let result = match parse_all_pfcp_ies(rest) {
                Ok(v) => v,
                Err(_) => Vec::new(),
            };
            pfcpinfo.ies = result;
            parsed_packet.app = AppLayerInfo::PFCP(pfcpinfo);
        },

        _ => {
        },
    };
}


pub async fn
parse_single_packet(path: &PathBuf, id: usize)
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
        let (np, l3_hdr_len) =
            parse_l3(next_type, &packet.data[offset..], &mut parsed_packet).await;

        offset += l3_hdr_len;
        next_type = np;

        if next_type != PROTO_TYPE_IPINIP {
            break;
        }
    }

    // --- Parse Layer 4 ---
    let (port_number, l4_hdr_len) =
        parse_l4(next_type, &packet.data[offset..], &mut parsed_packet).await;

    offset += l4_hdr_len;

    // --- Parse Application Layer ---
    parse_app(port_number, &packet.data[offset..], &mut parsed_packet).await;

    Ok(ParsedDetail {
        id,
        packet: parsed_packet
    })
}


pub async fn simple_parse_pcap(path: &Path)
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

    while let Ok(packet) = cap.next_packet() {

        let mut hdr_len = 0;
        let tot_len = packet.len();

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

        if next_type != NEXT_HDR_IPV4 && next_type != NEXT_HDR_IPV6 {
            idx += 1;
            continue;
        }

        hdr_len += MIN_ETH_HDR_LEN;

        // --- Parse Layer 3 ---
        let next_type= match next_type {
            //IPv4
            NEXT_HDR_IPV4 => {
                parse_ipv4_simple(&packet.data[hdr_len..], &mut parsed_packet)
            },

            //IPv6
            NEXT_HDR_IPV6 => {
                parse_ipv6_simple(&packet.data[hdr_len..], &mut parsed_packet)
            }
            _       => {
                idx+=1;
                continue;
            },
        };

        if next_type == 0 {
            idx += 1;
            continue;
        }

        hdr_len += IP_HDR_LEN;

        // --- Parse Layer 4 ---
        let (port_number, l4_hdr_len) =
            match next_type {
                PROTO_TYPE_TCP   => {
                    (
                        parse_tcp_simple ( &packet.data[hdr_len..], &mut parsed_packet),
                        TCP_HDR_LEN
                    )
                },

                PROTO_TYPE_UDP   => {
                    (
                        parse_udp_simple ( &packet.data[hdr_len..], &mut parsed_packet),
                        UDP_HDR_LEN
                    )
                },

                PROTO_TYPE_ICMP   => {
                    (
                        parse_icmp_simple ( &packet.data[hdr_len..], &mut parsed_packet),
                        ICMP_HDR_LEN
                    )
                },

                _       => {
                    idx+=1;
                    packets.push(parsed_packet);
                    continue;
                },
            };

        if port_number == 0 || l4_hdr_len == 0 {
            idx += 1;
            packets.push(parsed_packet);
            continue;
        }

        hdr_len += l4_hdr_len;

        parsed_packet.length = tot_len - hdr_len;
        // --- Parse Application Layer ---
        match port_number {
            L4_PORT_GTPV2   => {
                parsed_packet.protocol = "GTP2-C".to_string();
                let _ = parse_gtpc (
                        &packet.data[hdr_len..],
                        &mut parsed_packet);
            },

            L4_PORT_PFCP => {
                parsed_packet.protocol = "PCFP".to_string();
                let _ = parse_pfcp( &packet.data[hdr_len..],
                &mut parsed_packet);
            },

            _ => {
            },
        };

        idx += 1;
        packets.push(parsed_packet);
    }

    let packet_len = packets.len();

    let result = ParsedResult {
        file: path.to_string_lossy().to_string(),
        total_packets: packet_len,
        packets : packets,
    };

    Ok (result)
}
