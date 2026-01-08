use std::net::{Ipv4Addr, Ipv6Addr};
use serde::Serialize;
use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32},
    bytes::complete::take,
};
use std::convert::TryInto;

use crate::pfcp::types::*;
use crate::gtp::gtp_ie::*;

#[derive(Debug, Clone, Serialize)]
pub struct PfcpIe {
    pub ie_type: u16,
    pub type_str: String,
    pub ie_len: u16,
    pub ie_value: IeValue<PfcpIe>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FSeidValue {
    pub v4: bool,
    pub v6: bool,
    pub seid: u32,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}
impl FSeidValue {
    pub fn new() -> Self {
        FSeidValue {
            v4: true,
            v6: true,
            seid: 0,
            ipv4: None,
            ipv6: None,
        }
    }
}

fn decode_fseid<T>(input: &[u8])
    -> Result<IeValue<T>, String>
{
    if input.is_empty() {
        return Err("Input is empty".into());
    }

    let mut pos = 0;

    let v4 = input[pos] & 0x80 == 1;
    let v6 = input[pos] & 0x40 == 1;

    pos += 1;

    let seid = u32::from_be_bytes([
        input[pos], input[pos+1],
        input[pos+2], input[pos+2]
    ]);

    pos += 4;

    let ipv4 = if v4 {
        let addr = Ipv4Addr::from_octets(
                input[pos..pos+4].try_into().unwrap());
        pos += 4;
        Some(addr.to_string())
    }
    else {
        None
    };

    let ipv6 = if v6 {
        let addr = Ipv6Addr::from_octets(
                input[pos..pos+4].try_into().unwrap());
        pos += 16;
        Some(addr.to_string())
    }
    else {
        None
    };

    let fseid = FSeidValue {
        v4,
        v6,
        seid,
        ipv4,
        ipv6,
    };

    Ok(IeValue::FSeid(fseid))
}


fn parse_ie(input: &[u8])
    -> IResult<&[u8], PfcpIe>
{
    let (input, ie_type) = be_u16(input)?;
    let (input, ie_len) = be_u16(input)?;
    // let total_len = (ie_len + 4) as usize;
    let (rest, mut raw_value) = take(ie_len)(input)?;

    let (type_str, is_group) = PFCP_IE_TYPES
        .get(ie_type as usize)
        .map(|(s, g)| (s.to_string(), *g))
        .unwrap_or_else(|| ("Out of bound".to_string(), false));

    let mut ie = PfcpIe {
        ie_type,
        type_str,
        ie_len,
        ie_value: IeValue::None,
        raw: raw_value.to_vec(),
    };

    if is_group {
        let mut sub_ie : Vec<PfcpIe> = Vec::new();

        while raw_value.len() > 4 {
           match parse_ie(raw_value) {
            Ok((r, v)) => {
                sub_ie.push(v);
                raw_value = r;
            },
            Err (_) => {
                break;
            },
           }
        }
        ie.ie_value = IeValue::SubIeList(sub_ie);
    }
    else {
        let ie_value = match ie_type {
            PFCP_IE_F_SEID => 
                decode_fseid::<PfcpIe>(raw_value).unwrap_or(IeValue::None),
            _ =>
                match ie_len {
                    1 => IeValue::Uint8(raw_value[0]),
                    2 => IeValue::Uint16(u16::from_be_bytes([
                        raw_value[0], raw_value[1]]
                    )),
                    4 => IeValue::Uint32(u32::from_be_bytes([
                        raw_value[0], raw_value[1],
                        raw_value[2], raw_value[3]]
                    )),
                    _ => IeValue::Raw(raw_value.to_vec()),
                },
        };
        ie.ie_value = ie_value;
    }

    Ok((rest, ie))
}

pub fn parse_all_pfcp_ies(mut input: &[u8])
    -> Result<Vec<PfcpIe>, String>
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