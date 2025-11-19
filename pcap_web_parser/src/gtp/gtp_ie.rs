use std::net::{Ipv4Addr, Ipv6Addr};

// use std::result::Result::{Ok, Err};
use serde::Serialize;
use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32},
    bytes::complete::take,
};

use crate::types::*;
use crate::gtp::gtp::*;
use crate::gtp::gtpv2_types::*;

#[derive(Debug, Serialize)]
pub struct AmbrValue {
    pub ul: u32,
    pub dl: u32,
}

#[derive(Debug, Serialize)]
pub struct FTeidValue {
    pub v4: bool,
    pub v6: bool,
    pub iface_type: u8,
    pub teid: u32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServingNetworkValue {
    pub mcc: String,
    pub mnc: String,
}
#[derive(Debug, Serialize)]
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




#[derive(Debug, Serialize)]
pub struct TaiValue {
    pub mcc: String,
    pub mnc: String,
    pub tac: u16,
}

#[derive(Debug, Serialize)]
pub struct EcgiValue {
    pub mcc: String,
    pub mnc: String,
    pub eci: u32,   // 28-bit value, stored in u32
}
#[derive(Debug, Serialize)]
pub struct CgiValue {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
    pub ci: u16,
}
#[derive(Debug, Serialize)]
pub struct SaiValue {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
    pub sac: u16,
}


#[derive(Debug, Serialize)]
pub struct RaiValue {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
    pub rac: u8,
}
#[derive(Debug, Serialize)]
pub struct LaiValue {
    pub mcc: String,
    pub mnc: String,
    pub lac: u16,
}
#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
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

    // 복합 구조 (예: Bearer Context, Indication Flags 등)
    // SubIeList([GtpIe;5]),
    SubIeList(Vec<GtpIe>),

    None,
}

#[derive(Debug, Serialize)]
pub struct GtpIe {
    pub ie_type: u8,
    pub type_str: String,
    pub length: u16,
    pub instance: u8,
    // pub value: Vec<u8>,
    pub ie_value: GtpIeValue,
    // pub sub_ies: Vec<GtpIe>,
}

pub fn decode_mcc_mnc(d1: u8, d2: u8, d3: u8) -> (String, String)
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

pub fn parse_uli_ie(data: &[u8]) -> Result<GtpIeValue, String> {
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
        let eci = ((data[offset + 3] as u32) << 24)
                | ((data[offset + 4] as u32) << 16)
                | ((data[offset + 5] as u32) << 8)
                |  (data[offset + 6] as u32);
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

pub fn decode_serving_network(input: &[u8])
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
                input[pos..pos+3].try_into().unwrap());
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

    let ebi  = input[0] & 0x0F;;
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
        let len = input[pos] as usize;

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


pub fn decode_bcd(input: &[u8])
-> Result<GtpIeValue, String>
{
    if input.is_empty() {
        return Err("input is empty".into());
    }

    let mut digits = String::with_capacity(input.len() * 2);

    for &b in input {
        let low = (b & 0x0F) as u8;
        let high = ((b >> 4) & 0x0F) as u8;

        // low nibble must be 0..=9
        if low <= 9 {
            digits.push(char::from(b'0' + low));
        } else if high == 0x0F {
            // high nibble: if 0xF, it is filler -> odd length, stop adding second digit
            break;
        } else {
            return Err(format!("invalid BCD digit in low nibble: 0x{:x}", low));
        }

        if high <= 9 {
            digits.push(char::from(b'0' + high));
        } else {
            return Err(format!("invalid BCD digit in high nibble: 0x{:x}", high));
        }
    }

    Ok(GtpIeValue::Utf8String(digits))
}

pub fn parse_ie(input: &[u8])
-> IResult<&[u8], GtpIe>
{
    // let mut result = Vec::new();
    let (input, ie_type) = be_u8(input)?;
    let (input, ie_len) = be_u16(input)?;
    let (mut input, inst_byte) = be_u8(input)?;
    let ie_inst = inst_byte & 0x0f;


    let is_grouped = GTPV2_IE_TYPES[ie_type as usize].1;

    let mut sub_ies: Vec<GtpIe> = Vec::new();
    // let mut raw_value: Vec<u8> = Vec::new();

    let mut ret = GtpIeValue::None;
    if is_grouped {
        let mut remaining = &input[..ie_len as usize];

        while !remaining.is_empty() {
            match parse_ie(remaining) {
                Ok((rest, ie)) => {
                    sub_ies.push(ie);
                    remaining = rest;
                }
                Err(_) => break,
            }
        }
        input = &input[ie_len as usize..];
    }
    else {
        let (next, value) = take(ie_len)(input)?;
        
        let val = match ie_type {
            //IMSI, MSISDN
            1 | 75 | 76 => decode_bcd(value),

            //APN
            71 => decode_apn(value),

            //AMBR
            72 => decode_ambr(value),

            //EBI
            73 => decode_ebi(value),

            //BearerQoS
            80 => decode_bearerqos(value),

            //Serving Network
            83 => decode_serving_network(value),

            //ULI
            85 =>parse_uli_ie(value,),

            //F-TEID
            87 => decode_fteid(value),

            //Error
            _ => Ok(GtpIeValue::Raw(value.to_vec())),
        };

        ret = match val{
          Ok(v) => v,
          Err(e) => GtpIeValue::None,
        };

        input = next;
    }

    Ok( (input,
        GtpIe {
            ie_type,
            type_str: GTPV2_IE_TYPES[ie_type as usize].0.to_string(),
            length: ie_len,
            instance: ie_inst,
            ie_value: ret,
        },
    ))
}


pub fn parse_all_ies(mut input: &[u8]) -> Vec<GtpIe> {
    let mut result = Vec::new();

    while !input.is_empty () {
        match parse_ie(input) {
            Ok((rest, ie)) => {
                result.push(ie);
                input = rest;
            },

            Err(_) => break,
        }
    }

    result
}