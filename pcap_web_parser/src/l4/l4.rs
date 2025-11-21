use crate::ip::port::*;
use crate::types::*;
use crate::l4::udp::*;
use crate::l4::tcp::*;
use crate::l4::icmp::*;






pub fn preparse_layer4(proto_num:usize, l4: &[u8], packet: & mut PacketSummary) -> (u16, usize)
{
    let proto= protocol_to_str(proto_num);

    packet.protocol = proto.unwrap();

    match proto_num {
        6   =>  return (parse_tcp_simple(l4, packet), 20),
        17  => return (parse_udp_simple(l4, packet), 8),
        1   => return (parse_icmp_simple(l4, packet), 4),
        _   => {
            // println!("IP proto {}", proto_num);
            return (0, 0);
        }
    }
}