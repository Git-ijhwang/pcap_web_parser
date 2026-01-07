use std::net::{Ipv4Addr, Ipv6Addr};
use serde::Serialize;
use nom::{
    IResult,
    number::complete::{be_u8, be_u16, be_u32, be_u64},
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
    pub ie_value: IeValue,
    pub raw: Vec<u8>,
}

fn parse_ie(input: &[u8])
    -> IResult<&[u8], PfcpIe>
{
    let ie_type = u16::from_be_bytes([input[0], input[1]]);
    let ie_len = u16::from_be_bytes([input[2], input[3]]);
    let total_len = (ie_len + 4) as usize;
    let (input, _) = take(4usize)(input)?;

    let mut ie = PfcpIe {
        ie_type,
        type_str: PFCP_IE_TYPES[ie_type as usize].0.to_string(),
        ie_len,
        ie_value: IeValue::None,
        raw: input[..total_len].to_vec(),
    };

    Ok((input, ie))
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