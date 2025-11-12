use std::env;
use std::process;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};
// use tokio::fs::File;
use std::fs::File;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use tower_http::cors::CorsLayer;
use std::path::Path;
use chrono::format::format;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use pcap::{Capture, Packet};

use crate::ipv4::*;
use crate::ipv6::*;
use crate::l4::*;
use crate::gtpv2_types::*;
use crate::gtp::*;
use crate::{*};

pub const IP_HDR_LEN:usize = 20;
pub const MIN_ETH_HDR_LEN:usize = 14;

fn format_timestamp(packet: &Packet) -> String
{
    // pcap::Packet has a header with ts (timeval) fields on most platforms:
    // packet.header.ts.tv_sec and packet.header.ts.tv_usec
    // Use safe fallback if not present.
    let sec = packet.header.ts.tv_sec as i64;
    let usec = packet.header.ts.tv_usec as u32; // microseconds

    // Create naive datetime from seconds + microseconds
    let naive = NaiveDateTime::from_timestamp_opt(sec, usec * 1000)
        .unwrap_or_else(|| NaiveDateTime::from_timestamp_opt(sec, 0).unwrap());

    // let dt: DateTime<Local> = TimeZone::from_utc_datetime(naive, *Local::now().offset());
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
    println!("\tMAC:\n\t\t{}\n\t\t{}", src_mac, dst_mac );

    next_type
}

fn print_timestamp(idx:usize, packet: &Packet)
    -> String
{
    let ts = format_timestamp(packet);
    println!( "[{:05}] {}\tlen:{}", idx, ts, packet.header.len );
    format!( "{}",ts).to_string()
}

pub async fn parse_file(path: &Path) -> Result<ParsedResult, String> 
{
    // let args: Vec<String> = env::args().collect();

    // if args.len() < 2 {
    //     eprintln!("Usage {} Filename of pacp file short|long", args[0]);
    //     process::exit(1);
    // }

    let file = File::open(path)
        .map_err(|e| format!("File open error: {}", e))?;

    let filename = path;
    // let detail = &args[2];
    // let mut short: bool = false;

    // if detail.eq("short") {
        // short = true;
    // } else {
        let short = false;
    // }
    // println!("short {}", short);

    //read pcap file line by line
    let mut cap = match Capture::from_file(filename) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to open pcap file {}", path.to_string_lossy());
            process::exit(1);
        }
    };

    let mut idx: usize = 1;
    let mut packets: Vec<PacketSummary> = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        // Print Time stamp

        let mut parsed_packet : PacketSummary = PacketSummary::new();
        parsed_packet.id = idx;
        parsed_packet.ts = print_timestamp(idx, &packet);

        //Parse Layer 2 Ethernet
        let mut next_type = 0;
        if packet.data.len() >= MIN_ETH_HDR_LEN {
            //get next protocol from Ethernet
            next_type = parse_ethernet(&packet.data);
        }

        //Parse Layer 3
        // next_type
        let v= match next_type {
            //IPv4
            0x0800  => Some(parse_ipv4(&packet.data[14..], &mut parsed_packet)),
            //IPv6
            // 0x86dd  => Some(parse_ipv6(&packet.data[14..], short)),
            //ARP
            // 0x0806  => Some(parse_ipv4(&packet.data[14..], short)),
            _       => None,
        };

        if v.is_none() {
            break;
        }

        next_type = v.unwrap();

        //Parse Layer 4
        let (port_number, l4_hdr_len) =
            preparse_layer4(next_type, &packet.data[(MIN_ETH_HDR_LEN+IP_HDR_LEN)..], &mut parsed_packet);

        idx += 1;

        //Parse Application Layer
        match port_number {
            2123 => {
                match parse_gtpc(&packet.data[(MIN_ETH_HDR_LEN+IP_HDR_LEN+l4_hdr_len)..], &mut parsed_packet) {
                    Ok((_rest, hdr)) =>  {

                        let ies: Vec<GtpIe> = parse_all_ies(hdr.payload);
                        for ie in ies {
                            println!("\t\tIE:\n\t\t\tType:{}({}), len:{}, inst:{}",
                            GTPV2_IE_TYPES[ie.ie_type as usize],
                            ie.ie_type , ie.length, ie.instance);
                        }
                    }
                    Err(e) => println!("ERR {:?}", e),
                }
            }
            _ => {}
        }

        packets.push(parsed_packet);
    }

    if packets.len() == idx-1 {
        Ok(ParsedResult {
            total_packets: idx-1,
            packets
        })
    }
    else {
        println!(" Parse Fail. {}:{}", packets.len(), idx );
        Err("Fail".to_string())
    }
}
