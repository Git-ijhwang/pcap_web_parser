use std::net::Ipv4Addr;
use serde::Serialize;
use std::path::{Path, PathBuf};
use pcap::{Capture, Packet};

use crate::ip::{self, ipv4::*, ipv6::*, port::*};
use crate::l4::{tcp::*, udp::*, icmp::*};
use crate::gtp::{gtp::*, gtp_ie::*, gtpv2_types::*};
use crate::types::*;

#[derive(Serialize, Debug)]
pub struct CallFlow{
    pub src_addr: String,
    pub dst_addr: String,
    pub message: String,
    pub timestamp: String,
    pub id: usize,
}
impl CallFlow{
    pub fn new() -> Self {
        CallFlow {
            src_addr: String::new(),
            dst_addr: String::new(),
            message: String::new(),
            timestamp: String::new(),
            id: 0,
        }
    }
}


#[derive(Serialize, Debug)]
pub struct ip5tuple {
    pub protocol: u8,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}
impl ip5tuple{
    pub fn new() -> Self {
        ip5tuple {
            protocol: 0,
            src_addr: Ipv4Addr::new(0, 0, 0, 0),
            dst_addr: Ipv4Addr::new(0, 0, 0, 0),
            src_port: 0,
            dst_port: 0,
        }
    }
}

#[derive(Serialize, Debug)]
struct OwnedPacket {
    idx: i32,
    data: Vec<u8>,
}

fn get_seq_from_gtpc(input: &[u8]) -> u32 {

    let offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    let (_, hdr) = get_gtp_header(&input[offset..]).map_err(|e| {
        eprintln!("GTP Header parse error: {:?}", e);
        e
    }).unwrap();

    println!("GTP Sequence: {}", hdr.seq);

    hdr.seq
}


fn load_pcap(path: &PathBuf) -> Result<Vec<OwnedPacket>, String> {
    let mut cap = Capture::from_file(path)
        .map_err(|e| e.to_string())?;

    let mut idx: i32 = 1;
    let mut packets = Vec::new();

    while let Ok(pkt) = cap.next_packet() {
        packets.push(
            OwnedPacket { idx, data: pkt.data.to_vec() }
        );
        idx += 1;
    }

    Ok(packets)
}


async fn
extract_imsi(packet: &OwnedPacket)
// -> Result<GtpIeVal, String>
-> String
{
    let mut offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    let imsi = String::new();
    let hdr_size = get_gtp_hdr_len(&packet.data[offset..]);

    offset += hdr_size;

    let ies = parse_all_ies(&packet.data[offset..]);

    let imsi = match ies {
        Ok(ies) => {
            let t = find_ie_imsi(&ies);
            match t {
                Ok(imsi_value) => {
                    imsi_value
                },
                Err(e) => {
                    return imsi;
                }
            }
        },

        Err(e) => {
            return imsi;
        },
    };

    return imsi;
}


async fn
extract_5tuple(packet: &OwnedPacket)
-> ip5tuple
{
    let mut offset: usize = 0;
    let mut tuple = ip5tuple::new();

    offset += MIN_ETH_HDR_LEN;

    (tuple.src_addr, tuple.dst_addr) = get_ip_addr(&packet.data[offset..]);

    let proto = get_next_proto(
                &packet.data[offset..]);

    tuple.protocol = proto as u8;

    if PROTO_TYPE_UDP != proto as usize {
        return ip5tuple::new();
    }

    offset += IP_HDR_LEN;

    (tuple.src_port, tuple.dst_port) = get_udp_port(&packet.data[offset..]);

    tuple
}

fn filter_by_imsi(target_imsi: &str, packets: Vec<OwnedPacket>)
->Vec<OwnedPacket>
{
    let mut imsi_filtered_packets = Vec::new();

    println!("Target IMSI for filtering: {}", target_imsi);
    for pkt in packets.into_iter() {
        let mut offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
        let hdr_size = get_gtp_hdr_len(&pkt.data[offset..]);
        offset += hdr_size;
        let ies = parse_all_ies(&pkt.data[offset..]);

        let imsi = match ies {
            Ok(ies) => {
                let t = find_ie_imsi(&ies);
                match t {
                    Ok(imsi_value) => {
                        imsi_value
                    },
                    Err(e) => String::new(),
                }
            },

            Err(e) => String::new(),
        };

        println!("Extracted IMSI: {}", imsi);
        if imsi == target_imsi {
            imsi_filtered_packets.push(pkt);
        }

    }

    imsi_filtered_packets
}

async fn filter_by_teid(orig_teid:u32, filtered_packets: Vec<OwnedPacket>)
->Vec<OwnedPacket>
{
    let offset: usize = MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    filtered_packets.into_iter().filter(|pkt| {
        match get_gtp_teid(&pkt.data[offset..]) {
            Ok ((_, teid)) => teid == orig_teid,
            Err(_) => false,
        }
    }).collect()

}

async fn filter_by_5tuple(tuple:ip5tuple,
    vecPackets: Vec<OwnedPacket>
)
// ->Vec<Packet<'_>>
->Result<Vec<OwnedPacket>, String>
{
    let mut offset: usize = 0;
    let mut ip_filtered_packets = Vec::new();

    offset += MIN_ETH_HDR_LEN;

    // let pcap = &mut cap.cloned();
    // loop 대신 while let을 사용하여 깔끔하게 처리 가능
    // while let Ok(pkt) = cap.next_packet() 
    for pkt in vecPackets.into_iter() {
    
        let (src, dst) = get_ip_addr(&pkt.data[offset..]);
        let proto = get_next_proto(&pkt.data[offset..]);

        if (tuple.src_addr == src || tuple.src_addr == dst) &&
           (tuple.dst_addr == src || tuple.dst_addr == dst) &&
           tuple.protocol as usize == proto {
            
            ip_filtered_packets.push( pkt);
        }
    }

    if ip_filtered_packets.is_empty() {
        return Err("No packets found for 5-tuple".to_string());
    }

    offset += IP_HDR_LEN;

    let mut port_filtered_packets = Vec::new();

    for pkt in ip_filtered_packets {

        let (src_port, dst_port) = get_udp_port(&pkt.data[offset..]);

        if ( tuple.src_port == src_port || tuple.src_port == dst_port ) &&
           ( tuple.dst_port == src_port || tuple.dst_port == dst_port ) {
            port_filtered_packets.push(pkt);   
        }
    }

    Ok(port_filtered_packets)
}

fn
make_data( tuple_filtered_packets: Vec<OwnedPacket>)
-> Result<Vec<CallFlow>, String>
{
    let mut call_flow= Vec::new();

    for pkt in tuple_filtered_packets {
        let mut offset: usize = 0;
        let mut cf = CallFlow::new();

        // cf.timestamp = print_timestamp(idx, &packet);

        cf.id = pkt.idx as usize;

        offset += MIN_ETH_HDR_LEN;

        let (src_addr, dst_addr) = get_ip_addr(&pkt.data[offset..]);

        cf.src_addr.push_str(&src_addr.to_string());
        cf.dst_addr.push_str(&dst_addr.to_string());

        offset += IP_HDR_LEN+UDP_HDR_LEN;

        let (input, message) = get_msg_type_from_gtpc (&pkt.data[offset..]).map_err(|e| format!("Error: {:?}", e))?;

        cf.message.push_str(&message);

        call_flow.push(cf);
    }

    return Ok(call_flow);
}


pub async fn
make_call_flow (path: &PathBuf, id: usize)
-> Result<Vec<CallFlow>, String>
{
    let mut offset: usize = 0;

    //1. convert pcap to vec
    let vecPackets = load_pcap(path)?;

    //2. find the packet by id
    let packet =vecPackets.get(id).ok_or("Packet not found".to_string())?;

    //3. extract 5-tuple from previous found packet
    let tuple = extract_5tuple(&packet).await;
    println!("Extracted 5-tuple: {:?}", tuple);

    offset += MIN_ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    //4. extract TEID from previous found packet
    // let (rest,  teid) = get_gtp_teid(&packet.data[offset..]).map_err(|e| format!("GTP-C parse error: {:?}", e))?;
    // println!("Extracted TEID: {}", teid);

    let target_imsi = extract_imsi(&packet).await;

    //5. Filter by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol_type) of found previous packet
    let filtered_packets = filter_by_5tuple(tuple, vecPackets).await;

    //5.1 Handle error from filtering by 5-tuple
    let tuple_filtered_packets = match filtered_packets {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error filtering by 5-tuple: {}", e);
            return Err("Error filtering by 5-tuple".to_string());
        }
    };
    // println!("Filtered packets count: {}", tuple_filtered_packets.len());

    /*

    //6. Filter by TEID of found previous packet
    let teid_filtered_packets = filter_by_teid(teid, tuple_filtered_packets).await;
    println!("TEID Filtered packets count: {}", teid_filtered_packets.len());
    */

    let imsi_filtered_packets = filter_by_imsi(&target_imsi, tuple_filtered_packets);
    println!("IMSI Filtered packets count: {}", imsi_filtered_packets.len());

    //7. Make Call Flow raw data
    let call_flow = make_data( imsi_filtered_packets);

    println!("Call Flow constructed with\n{:?}", call_flow);
    return call_flow;
}