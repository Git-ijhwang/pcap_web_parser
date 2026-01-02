use std::net::{Ipv4Addr, Ipv6Addr};
use serde::Serialize;
use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32},
    bytes::complete::take,
};
use std::convert::TryInto;

use crate::gtp::gtpv2_types::*;

#[derive(Debug, Clone, Serialize)]
pub struct AmbrValue {
    pub ul: u32,
    pub dl: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct FTeidValue {
    pub v4: bool,
    pub v6: bool,
    pub iface_type: u8,
    pub teid: u32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}
impl FTeidValue {
    pub fn new() -> Self {
        FTeidValue {
            v4: true,
            v6: true,
            iface_type: 0,
            teid: 0,
            ipv4: None,
            ipv6: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServingNetworkValue {
    pub mcc: String,
    pub mnc: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct BearerQoSValue {
    pub pci: bool,
    pub pl: u8,
    pub pvi: bool,
    pub qci: u8,

    pub mbr_ul: u32,
    pub mbr_dl: u32,
    pub gbr_ul: u32,
    pub gbr_dl: u32,
}


#[derive(Debug, Clone, Serialize)]
pub struct TaiValue {
    pub mcc: String,
    pub mnc: String,
    pub tac: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct EcgiValue {
    pub mcc: String,
    pub mnc: String,
    pub eci: u32,   // 28-bit value, stored in u32
}
#[derive(Debug, Clone, Serialize)]
pub struct CgiValue {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
    pub ci: u16,
}
#[derive(Debug, Clone, Serialize)]
pub struct SaiValue {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
    pub sac: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct RaiValue {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
    pub rac: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaiValue {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
}

#[derive(Debug, Clone, Serialize)]
pub enum PacketFilterComponent {
    Ipv4Addr { addr: String, mask: String },      // IPv4 address + mask (8 bytes)
    Ipv6Addr { addr: String, mask: String },      // IPv6 address + mask (32 bytes: 16+16)
    Protocol { proto: u8 },                       // Protocol ID / Next Header (1 byte)
    SinglePort { port: u16 },                     // single port (2 bytes)
    PortRange { start: u16, end: u16 },           // port range (4 bytes)
    SecParamIdx { spi: u32 },                     // Protocol ID / Next Header (1 byte)
    TypeOfService { value: u8, mask: u8 },        // Protocol ID / Next Header (1 byte)
    FlowLabel { label: u32 },
    Unknown { t: u8, data: Vec<u8> },             // unknown selector
    None,
}

static BEARER_TFT_OP_CODE: [&str;8] = [
    "Spare",                                    /* 0 0 0 [0]*/
    "Create New TFT",                           /* 0 0 1 [1]*/
    "Deleting existing TFT",                    /* 0 1 0 [2]*/
    "Add packet filters to existing TFT",       /* 0 1 1 [3]*/
    "Replace packet filter in existing TFT",    /* 1 0 0 [4]*/
    "Delete packet filter in existing TFT",     /* 1 0 1 [5]*/
    "No TFT operation",                         /* 1 1 0 [6]*/
    "Reserved",                                 /* 1 1 1 [7]*/
];

#[derive(Debug, Clone, Serialize)]
pub struct PacketFilterComponentList {
    pub pf_type_id: u8,
    pub components: PacketFilterComponent, 
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketFilter {
    pub pf_dir: u8,
    pub pf_id: u8,
    pub pkt_prec: u8,
    pub pf_len: u8,
    pub packet_filter_component_list: Vec<PacketFilterComponentList>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BearerTFT {
    pub tft_op_code: u8,
    pub str_tft_op_code: String,
    pub e_bit: bool,
    pub num_filter: u8,
    pub packet_filter_list: Vec<PacketFilter>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UliValue {
    pub has_tai: bool,
    pub has_ecgi: bool,
    pub has_lai: bool,
    pub has_rai: bool,
    pub has_sai: bool,
    pub has_cgi: bool,

    pub tai: Option<TaiValue>,
    pub ecgi: Option<EcgiValue>,
    pub lai: Option<LaiValue>,
    pub rai: Option<RaiValue>,
    pub sai: Option<SaiValue>,
    pub cgi: Option<CgiValue>,
}

#[derive(Debug, Clone, Serialize)]
pub enum GtpIeValue {
    // Raw bytes (해석되지 않은 기본 형태)
    Raw(Vec<u8>),

    // 단순 정수
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),

    // 문자열
    Utf8String(String),
    Apn(String),

    // IPv4, IPv6
    Ipv4(String),
    Ipv6(String),

    // Timer
    Timer { unit: u8, value: u8 },

    // 2. Composite-but-not-grouped
    Ambr(AmbrValue),
    FTeid(FTeidValue),
    ServingNetwork(ServingNetworkValue),
    BearerQoS(BearerQoSValue),
    UserLocationInfo(UliValue),
    BearerTFT(BearerTFT),

    SubIeList(Vec<GtpIe>),

    None,
}


#[derive(Debug, Clone, Serialize)]
pub struct GtpIe {
    pub ie_type: u8,
    pub type_str: String,
    pub length: u16,
    pub instance: u8,
    pub ie_value: GtpIeValue,
    pub raw: Vec<u8>,
}


pub fn decode_mcc_mnc(d1: u8, d2: u8, d3: u8)
    -> (String, String)
{
    let mcc = format!("{}{}{}", d1 & 0x0F, d1 >> 4, d2 & 0x0F);
    let mnc1 = d2 >> 4;
    let mnc2 = d3 & 0x0F;
    let mnc3 = d3 >> 4;

    let mnc = if mnc3 == 0xF {
        // MNC = 2-digit
        format!("{}{}", mnc1, mnc2)
    } else {
        // MNC = 3-digit
        format!("{}{}{}", mnc1, mnc2, mnc3)
    };

    (mcc, mnc)
}

pub fn parse_uli_ie(data: &[u8])
    -> Result<GtpIeValue, String>
{
    if data.len() < 1 {
        return Err("ULI IE too short".into());
    }

    let flags = data[0];
    let mut offset = 1;

    let mut uli = UliValue {
        has_cgi: flags & 0x01 != 0,
        has_sai: flags & 0x02 != 0,
        has_rai: flags & 0x04 != 0,
        has_tai: flags & 0x08 != 0,
        has_ecgi: flags & 0x10 != 0,
        has_lai: flags & 0x20 != 0,
        cgi: None,
        sai: None,
        rai: None,
        tai: None,
        ecgi: None,
        lai: None,
    };

    // CGI (7 bytes)
    if uli.has_cgi {
        if data.len() < offset + 7 {
            return Err("CGI field incomplete".into());
        }
        let (mcc, mnc) = decode_mcc_mnc(data[offset], data[offset + 1], data[offset + 2]);
        let lac = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
        let ci = u16::from_be_bytes([data[offset + 5], data[offset + 6]]);
        uli.cgi = Some(CgiValue { mcc, mnc, lac, ci });
        offset += 7;
    }

    // SAI (7 bytes)
    if uli.has_sai {
        if data.len() < offset + 7 {
            return Err("SAI field incomplete".into());
        }
        let (mcc, mnc) = decode_mcc_mnc(data[offset], data[offset + 1], data[offset + 2]);
        let lac = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
        let sac = u16::from_be_bytes([data[offset + 5], data[offset + 6]]);
        uli.sai = Some(SaiValue { mcc, mnc, lac, sac });
        offset += 7;
    }

    // RAI (6 bytes)
    if uli.has_rai {
        if data.len() < offset + 6 {
            return Err("RAI field incomplete".into());
        }
        let (mcc, mnc) = decode_mcc_mnc(data[offset], data[offset + 1], data[offset + 2]);
        let lac = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
        let rac = data[offset + 5];
        uli.rai = Some(RaiValue { mcc, mnc, lac, rac });
        offset += 6;
    }

    // TAI (5 bytes)
    if uli.has_tai {
        if data.len() < offset + 5 {
            return Err("TAI field incomplete".into());
        }
        let (mcc, mnc) = decode_mcc_mnc(data[offset], data[offset + 1], data[offset + 2]);
        let tac = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
        uli.tai = Some(TaiValue { mcc, mnc, tac });
        offset += 5;
    }

    // ECGI (7 bytes)
    if uli.has_ecgi {
        if data.len() < offset + 7 {
            return Err("ECGI field incomplete".into());
        }
        let (mcc, mnc) = decode_mcc_mnc(data[offset], data[offset + 1], data[offset + 2]);
        let eci = ((data[offset + 3] as u32) << 24) |
                ((data[offset + 4] as u32) << 16) |
                ((data[offset + 5] as u32) << 8) |
                (data[offset + 6] as u32);
        uli.ecgi = Some(EcgiValue { mcc, mnc, eci });
        offset += 7;
    }

    // LAI (5 bytes)
    if uli.has_lai {
        if data.len() < offset + 5 {
            return Err("LAI field incomplete".into());
        }
        let (mcc, mnc) = decode_mcc_mnc(data[offset], data[offset + 1], data[offset + 2]);
        let lac = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
        uli.lai = Some(LaiValue { mcc, mnc, lac });
        offset += 5;
    }

    Ok(GtpIeValue::UserLocationInfo(uli))
}


fn parse_ipv4_remote(data: &[u8])
    -> Result<PacketFilterComponent, String>
{
    // commonly IPv4 component is 8 bytes: 4 bytes address + 4 bytes mask
    if data.len() < 8 {
        return Err(format!("IPv4 component length must be 8, got {}", data.len()));
    }

    let addr = Ipv4Addr::from(<[u8;4]>::try_from(&data[0..4]).unwrap()).to_string();
    let mask = Ipv4Addr::from(<[u8;4]>::try_from(&data[4..8]).unwrap()).to_string();

    Ok(PacketFilterComponent::Ipv4Addr { addr, mask })
}

fn parse_ipv6_remote(data: &[u8])
    -> Result<PacketFilterComponent, String>
{
    // commonly IPv6 component is 32 bytes: 16 bytes addr + 16 bytes mask
    if data.len() < 32 {
        return Err(format!("IPv6 component length must be 32, got {}", data.len()));
    }
    let addr = Ipv6Addr::from(<[u8;16]>::try_from(&data[0..16]).unwrap()).to_string();
    let mask = Ipv6Addr::from(<[u8;16]>::try_from(&data[16..32]).unwrap()).to_string();
    Ok(PacketFilterComponent::Ipv6Addr { addr, mask })
}

fn parse_protocol(data: &[u8])
    -> Result<PacketFilterComponent, String>
{
    if data.len() < 1 {
        return Err(format!("Protocol component length must be 1, got {}", data.len()));
    }
    Ok(PacketFilterComponent::Protocol { proto: data[0] })
}

fn parse_single_local_port(data: &[u8])
    -> Result<PacketFilterComponent, String>
{
    if data.len() < 2 {
        return Err(format!("Single port component length must be 2, got {}", data.len()));
    }
    let port = u16::from_be_bytes(data[0..2].try_into().unwrap());
    Ok(PacketFilterComponent::SinglePort { port })
}

fn parse_local_port_range(data: &[u8])
    -> Result<PacketFilterComponent, String>
{
    if data.len() < 4 {
        return Err(format!("Port range component length must be 4, got {}", data.len()));
    }
    let start = u16::from_be_bytes(data[0..2].try_into().unwrap());
    let end = u16::from_be_bytes(data[2..4].try_into().unwrap());

    Ok(PacketFilterComponent::PortRange { start, end })
}

fn parse_single_remote_port(data: &[u8])
    -> Result<PacketFilterComponent, String>
{
    if data.len() < 2 {
        return Err(format!("Single port component length must be 2, got {}", data.len()));
    }

    let port = u16::from_be_bytes(data[0..2].try_into().unwrap());
    Ok(PacketFilterComponent::SinglePort { port })
}

fn parse_remote_port_range(data: &[u8])
    -> Result<PacketFilterComponent, String>
{
    if data.len() < 4 {
        return Err(format!("Port range component length must be 4, got {}", data.len()));
    }
    let start = u16::from_be_bytes(data[0..2].try_into().unwrap());
    let end = u16::from_be_bytes(data[2..4].try_into().unwrap());

    Ok(PacketFilterComponent::PortRange { start, end })
}


// Security parameter index (SPI) – 4 bytes
fn parse_spi(comp_value: &[u8])
    -> Result<PacketFilterComponent, String>
{
    if comp_value.len() < 4 {
        return Err("SPI must be 4 bytes".into());
    }
    let spi = u32::from_be_bytes(comp_value.try_into().unwrap());
    Ok(PacketFilterComponent::SecParamIdx{spi})
}

// Type of Service / Traffic class (2 bytes)
fn parse_tos(comp_value: &[u8])
    -> Result<PacketFilterComponent, String>
{
    if comp_value.len() < 2 {
        return Err("TOS/Traffic class must be 2 bytes".into());
    }
    Ok(PacketFilterComponent::TypeOfService {
        value: comp_value[0],
        mask: comp_value[1],
    })
}

// Flow label (3 bytes)
fn parse_flow_label(comp_value: &[u8])
    -> Result<PacketFilterComponent, String>
{
    if comp_value.len() < 3 {
        return Err("Flow label must be 3 bytes".into());
    }
    let label =
        ((comp_value[0] as u32) << 16) |
        ((comp_value[1] as u32) << 8) |
         (comp_value[2] as u32);

    Ok(PacketFilterComponent::FlowLabel{label})
}

pub fn decode_bearer_tft (input: &[u8])
    -> Result<GtpIeValue, String>
{
    if input.len() < 3 {
        return Err("ServingNetwork IE: length must be more than 3 bytes".into());
    }

    let mut offset = 0;
    let tft_op_code = (input[0] & 0xE0) >> 5;
    let e_bit = (input[0] & 0x10) != 0;
    let num_filter = input[0] & 0x0F;
    offset += 1;

    let mut bearer_tft = BearerTFT {
        tft_op_code,
        str_tft_op_code: BEARER_TFT_OP_CODE[tft_op_code as usize].to_string(),
        e_bit,
        num_filter,
        packet_filter_list: Vec::new(),
    };

    for _ in 0..num_filter  {
        if offset + 4 >= input.len() {
            return Err("BearerTFT: packet filter header truncated".into());
        }

        // Common part of each PacketFilter
        let byte = input[offset];
        let pf_dir = (byte & 0x30) >> 4;
        let pf_id = byte & 0x0f;
        offset += 1;

        let pkt_prec = input[offset];
        offset += 1;

        let pf_len =  input[offset];
        offset += 1;


        // sanity check: pf_len bytes must exist
        if offset + (pf_len as usize) > input.len() {
            return Err("BearerTFT: packet filter content truncated".into());
        }

        // parse PF Content as TLV-like sequence of components
        let mut comp_offset = 0usize;
        let pf_content = &input[offset..offset + (pf_len as usize)];


        let mut component_list: Vec<PacketFilterComponentList> = Vec::new();
        let mut components: PacketFilterComponent = PacketFilterComponent::None;

        while comp_offset < pf_content.len() {

            if comp_offset +2 > pf_content.len() {
                component_list.push(PacketFilterComponentList {
                    pf_type_id: 0xff,
                    components: (PacketFilterComponent::Unknown {
                        t: 0xff, data: pf_content[comp_offset..].to_vec(),
                    }),
                });
                break;
            }

            // Packet filter component type identifier
            let comp_type = pf_content[comp_offset];
            comp_offset += 1;

            let comp_len = pf_len as usize-comp_offset as usize;
            // let comp_len = pf_content[pf_len as usize-comp_offset] as usize;
            // comp_offset += 1;

            if comp_offset + comp_len > pf_content.len() {
                component_list.push(PacketFilterComponentList {
                    pf_type_id: comp_type,
                    components: (PacketFilterComponent::Unknown {
                        t: comp_type,
                        data: pf_content[comp_offset..].to_vec(),
                    }),
                });
                break;
            }
            let real_len = match comp_type {
                0x10 => 8,
                0x20 => 32,
                0x30 => 1,

                0x40 => 2,
                0x41 => 4,
                0x50 => 2,
                0x51 => 4,

                0x60 => 4,
                0x70 => 2,
                0x80 => 3,
                _ => 0,
            };

            let comp_value = &pf_content[comp_offset..(comp_offset + real_len)];
            // let comp_value = &pf_content[comp_offset..(comp_offset + comp_len)];

            /*
            Packet filter component type identifier
            Bits
            8 7 6 5  4 3 2 1 
            0 0 0 1  0 0 0 0	IPv4 remote address type [0x10]
            0 0 1 0  0 0 0 0	IPv6 remote address type [0x20]
            0 0 1 1  0 0 0 0	Protocol identifier/Next header type [0x30]
            0 1 0 0  0 0 0 0	Single local port type [0x40]
            0 1 0 0  0 0 0 1	Local port range type [0x41]
            0 1 0 1  0 0 0 0	Single remote port type [0x50]
            0 1 0 1  0 0 0 1	Remote port range type [0x51]
            0 1 1 0  0 0 0 0	Security parameter index type [0x60]
            0 1 1 1  0 0 0 0	Type of service/Traffic class type [0x70]
            1 0 0 0  0 0 0 0	Flow label type [0x80]
            */

            let parsed_comp = match comp_type {
                0x10 => parse_ipv4_remote(comp_value),
                0x20 => parse_ipv6_remote(comp_value),
                0x30 => parse_protocol(comp_value),

                0x40 => parse_single_local_port(comp_value),
                0x41 => parse_local_port_range(comp_value),
                0x50 => parse_single_remote_port(comp_value),
                0x51 => parse_remote_port_range(comp_value),

                0x60 => parse_spi(comp_value),
                0x70 => parse_tos(comp_value),
                0x80 => parse_flow_label(comp_value),
                _ => Err(format!(" component type: 0x{:02X}", comp_type)),
            };

            components = match parsed_comp {
                Ok(v) => v,
                Err(e) => {
                    return Err("Error while parsing TFT Component".to_string());
                },
            };

            component_list.push( PacketFilterComponentList{
                        pf_type_id: comp_type,
                        components,
                    });

            // components.push(parsed_comp);
            // comp_offset += comp_len;
            comp_offset += real_len;
        }

        offset += pf_len as usize;


        let pkt_filter = PacketFilter {
            pf_dir,
            pf_id,
            pkt_prec,
            pf_len,
            packet_filter_component_list: component_list,
        };


        bearer_tft.packet_filter_list.push(pkt_filter);
    }

    Ok(GtpIeValue::BearerTFT(bearer_tft))
}

pub fn decode_serving_network( input: &[u8])
    -> Result<GtpIeValue, String>
{
    if input.len() < 3 {
        return Err("ServingNetwork IE: length must be 3".into());
    }

    // 3-byte MCC/MNC
    let b1 = input[0];
    let b2 = input[1];
    let b3 = input[2];

    let (mcc, mnc) = decode_mcc_mnc(b1, b2, b3);

    let sn = ServingNetworkValue {
        mcc,
        mnc,
    };

    Ok(GtpIeValue::ServingNetwork(sn))
}


pub fn decode_fteid(input: &[u8])
    -> Result<GtpIeValue, String>
{
    if input.is_empty() {
        return Err("input is empty".into());
    }
    let mut pos = 0;

    let v4:bool = input[0] & 0x80 != 0;
    let v6:bool = input[0] & 0x40 != 0;
    let iface_type = input[0] & 0x3f;

    pos += 1;

    if input.len() < pos +4 {
        return Err("F-TEID IE to short for TEID".into());
    }

    let teid = u32::from_be_bytes([
        input[pos],
        input[pos+1],
        input[pos+2],
        input[pos+3],
    ]);

    pos += 4;

    let  ipv4 = if v4 {
        if input.len() < pos +4 {
            return Err("F-TEID IE to short for TEID".into());
        }

        let addr = Ipv4Addr::from_octets(
                input[pos..pos+4].try_into().unwrap()  
            );

        
        pos += 4;
        Some(addr.to_string())
    }
    else {
        None
    };

    let  ipv6 = if v6 {
        if input.len() < pos + 16 {
            return Err("F-TEID IE to short for TEID".into());
        }

        let addr = Ipv6Addr::from_octets(
                input[pos..pos+16].try_into().unwrap() );
        pos += 16;
        Some(addr.to_string())
    }
    else {
        None
    };

    let fteid = FTeidValue {
        v4,
        v6,
        iface_type,
        teid,
        ipv4,
        ipv6,
    };

    Ok(GtpIeValue::FTeid(fteid))
}


pub fn decode_bearerqos(input: &[u8])
    -> Result<GtpIeValue, String>
{
    if input.is_empty() {
        return Err("input is empty".into());
    }
    let mut pos = 0;

    let pci:bool = input[0] & 0x40 != 0;
    let pl  = (input[0] & 0x3C) >> 2;
    let pvi:bool  = input[0] & 0x01 != 0;
    pos += 1;

    let qci = input[pos];
    pos += 1;

    // let input[pos]
    let mbr_ul = u32::from_be_bytes([
                input[pos], input[pos+1],
                input[pos+2], input[pos+3]
            ]);
    pos += 4;

    let mbr_dl = u32::from_be_bytes([
                input[pos], input[pos+1],
                input[pos+2], input[pos+3]
            ]);
    pos += 4;

    let gbr_ul = u32::from_be_bytes([
                input[pos], input[pos+1],
                input[pos+2], input[pos+3]
            ]);
    pos += 4;

    let gbr_dl = u32::from_be_bytes([
                input[pos], input[pos+1],
                input[pos+2], input[pos+3]
            ]);
    pos += 4;

    let qos = BearerQoSValue{
        pci,
        pl,
        pvi,
        qci,
        mbr_ul,
        mbr_dl,
        gbr_ul,
        gbr_dl,
    };
    Ok(GtpIeValue::BearerQoS(qos))

}


pub fn decode_ambr(input: &[u8])
    -> Result<GtpIeValue, String>
{
    if input.is_empty() {
        return Err("input is empty".into());
    }
    let mut pos = 0;

    let uplink = u32::from_be_bytes(
            [input[pos],
            input[pos+1],
            input[pos+2],
            input[pos+3]]);

    pos += 4;

    let dnlink = u32::from_be_bytes(
            [input[pos],
            input[pos+1],
            input[pos+2],
            input[pos+3]]);

    let ambr = AmbrValue{
        ul:uplink,
        dl:dnlink
    };
    Ok(GtpIeValue::Ambr(ambr))
}


pub fn decode_ebi(input: &[u8])
    -> Result<GtpIeValue, String>
{
    if input.is_empty() {
        return Err("input is empty".into());
    }

    let ebi  = input[0] & 0x0F;

    Ok(GtpIeValue::Uint8(ebi))
}

pub fn decode_apn(input: &[u8])
    -> Result<GtpIeValue, String>
{
    if input.is_empty() {
        return Err("input is empty".into());
    }

    let mut pos = 0;
    let mut labels = Vec::new();

    while pos < input.len() {
        let len = input.len() as usize;

        if len == 0 {
            return Err("Invalied APN format: zero-length buffer".into());
        }

        let label = &input[pos..pos+len];
        pos += len;

        match std::str::from_utf8(label) {
            Ok(s) => labels.push(s.to_string()),
            Err(_) => return Err("APN contains invalid UTF-8".into()),
        }
    }

    let apn = labels.join(".");

    Ok(GtpIeValue::Apn(apn))
}

pub fn decode_ipv4(input: &[u8])
    -> Result<GtpIeValue, String>
{
    let v = Ipv4Addr::from_octets([
        input[0], input[1], input[2], input[3]
    ]);
    let ip = v.to_string();
    Ok(GtpIeValue::Ipv4 (ip))
}


pub fn decode_bcd(input: &[u8])
    -> Result<GtpIeValue, String>
{
    if input.is_empty() {
        return Err("BCD input empty".into());
    }

    let mut digits = String::new();

    for (i, byte) in input.iter().enumerate() {
        let low = byte & 0x0F;
        let high = (byte >> 4) & 0x0F;

        // 첫 바이트 high nibble은 Odd/Even indicator라 스킵해도 됨.
        if i == 0 {
            // lower nibble = first digit
            if low <= 9 {
                digits.push(char::from(b'0' + low));
            }
            continue;
        }

        // 일반 BCD 처리
        if low <= 9 {
            digits.push(char::from(b'0' + low));
        }
        if high <= 9 {
            digits.push(char::from(b'0' + high));
        }
    }

    Ok(GtpIeValue::Utf8String(digits))
}


pub fn find_ie_bearer_ctx(ies: &Vec<GtpIe>)
    -> Result<Vec<Vec<GtpIe>>, String>
{
    let mut bearer_ctx_list = Vec::new();

    for ie in ies {
        if ie.ie_type == GTPV2C_IE_BEARER_CONTEXT {
            match &ie.ie_value {
                GtpIeValue::SubIeList(v) => {
                    bearer_ctx_list.push(v.clone());
                    // return Ok (v.clone());
                }
                _ => {
                    return Err("FTEID IE has unexpected value type".to_string());
                },
            }
        }
    }

    if bearer_ctx_list.is_empty() {
        Err("BEARER CONTEXT IE not found".to_string())
    }
    else {
        Ok(bearer_ctx_list)
    }
}

pub fn find_ie_fteid(ies: &Vec<GtpIe>)
    -> Result<Vec<FTeidValue>, String>
{
    let mut fteid_list = Vec::new();

    for ie in ies {
        if ie.ie_type == GTPV2C_IE_FTEID {
            match &ie.ie_value {
                GtpIeValue::FTeid(fteid) => {
                    // return Ok(fteid.clone());
                    fteid_list.push(fteid.clone());
                }
                _ => {
                    return Err("FTEID IE has unexpected value type".to_string());
                },
            }
        }
    }

    if fteid_list.is_empty() {
        Err("FTIED IE not found".to_string())
    }
    else  {
        Ok(fteid_list)
    }
}

pub fn find_ie_imsi(ies: &Vec<GtpIe>)
    -> Result<String, String>
{
    for ie in ies {
        if ie.ie_type == GTPV2C_IE_IMSI {
            match &ie.ie_value {
                GtpIeValue::Utf8String(s) => {
                    return Ok(s.clone());
                }
                _ => {
                    return Err("IMSI IE has unexpected value type".to_string());
                },
            }
        }
    }

    Err("IMSI IE not found".to_string())
}

pub fn find_ie_ebi_in_bearer_ctx(ies: &Vec<GtpIe>)
    -> Result<u8, String>
{
    for ie in ies {
        if ie.ie_type == GTPV2C_IE_EBI {
            match &ie.ie_value {
                GtpIeValue::Uint8(s) => {
                    return Ok(s.clone());
                }
                _ => {
                    return Err("IMSI IE has unexpected value type".to_string());
                },
            }
        }
    }
    Err("EBI IE not found".to_string())
}


pub fn find_ie_ebi(ies: &Vec<GtpIe>)
    -> Result<u8, String>
{
    for ie in ies {
        if ie.ie_type == GTPV2C_IE_EBI {
            match &ie.ie_value {
                GtpIeValue::Uint8(s) => {
                    return Ok(s.clone());
                }
                _ => {
                    return Err("IMSI IE has unexpected value type".to_string());
                },
            }
        }
    }
    Err("EBI IE not found".to_string())
}

pub fn parse_ie(input: &[u8])
    -> IResult<&[u8], GtpIe>
{
    let ie_type = input[0];
    let ie_len = u16::from_be_bytes([input[1], input[2]]) as usize;
    let ie_inst = input[3] & 0x0f;
    let total_len = 4+ie_len;

    let raw = input[..total_len].to_vec();

    let (mut input, _) = be_u32(input)?;

    let mut gtp_ie = GtpIe {
        ie_type,
        type_str: GTPV2_IE_TYPES[ie_type as usize].0.to_string(),
        length: ie_len as u16,
        instance: ie_inst,

        ie_value: GtpIeValue::None,
        raw,
    };

    let is_grouped = GTPV2_IE_TYPES[ie_type as usize].1;

    if is_grouped {
        let mut sub_ies: Vec<GtpIe> = Vec::new();
        let mut remaining = &input[..ie_len as usize];

        while !remaining.is_empty() {
            match parse_ie(remaining) {
                Ok((rest, ie)) => {
                    sub_ies.push(ie);
                    remaining = rest;

                    if remaining.len() < 4 {
                        break;
                    }
                }
                Err(_) => {
                    break;
                },
            }
        }
        gtp_ie.ie_value = GtpIeValue::SubIeList(sub_ies);

        input = &input[ie_len as usize..];
    }
    else {
        let (next, value) = take(ie_len)(input)?;
        
        let val = match ie_type {
            GTPV2C_IE_IMSI
            | GTPV2C_IE_MEI
            | GTPV2C_IE_MSISDN => decode_bcd(value),

            GTPV2C_IE_APN =>
                decode_apn(value),

            GTPV2C_IE_AMBR =>
                decode_ambr(value),

            GTPV2C_IE_EBI =>
                decode_ebi(value),

            GTPV2C_IE_BEARER_QOS =>
                decode_bearerqos(value),

            GTPV2C_IE_SERVING_NETWORK =>
                decode_serving_network(value),

            GTPV2C_IE_BEARER_TFT =>
                decode_bearer_tft(value),

            GTPV2C_IE_ULI =>
                parse_uli_ie(value,),

            GTPV2C_IE_FTEID =>
                decode_fteid(value),
                
            GTPV2C_IE_IP_ADDRESS =>
                decode_ipv4(value),

            _ =>  match ie_len {
                    1 =>  Ok(GtpIeValue::Uint8(value[0] )),
                    2 => {
                        let v = u16::from_be_bytes([value[0],value[1]]);
                        Ok(GtpIeValue::Uint16(v))
                    },
                    4 =>  match ie_type {
                        _ => {
                            let v = u32::from_be_bytes([ value[0], value[1], value[2], value[3] ]);
                            Ok(GtpIeValue::Uint32(v))
                        }
                    }
                    _ => Ok(GtpIeValue::Raw(value.to_vec())),
                },
        };

        gtp_ie.ie_value = val.unwrap_or(GtpIeValue::None);
        input = next;
    }

    Ok( (input, gtp_ie))
}


pub fn parse_all_ies(mut input: &[u8])
    -> Result<Vec<GtpIe>, String>
{
    let mut result = Vec::new();

    while !input.is_empty () {
        match parse_ie(input) {
            Ok((rest, ie)) => {
                result.push(ie);
                input = rest;
                if input.len() < 4 {
                    break;
                }
            },

            Err(e) => {
                return Err(format!("IE parse error: {}",e));
            }
        }
    }

    Ok(result)
}