import React from "react";
import TcpHeader from "./TcpHeader";
import UdpHeader from "./UdpHeader";
import IcmpHeader from "./IcmpHeader";

export default function Layer4Header({ l4 }) {
  console.log("TCP");
  if (l4.TCP) return <TcpHeader tcp={l4.TCP} />;

  console.log("UDP");
  if (l4.UDP) return <UdpHeader udp={l4.UDP} />;

  console.log("ICMP");
  if (l4.ICMP) return <IcmpHeader icmp={l4.ICMP} />;
  return <p>Unknown Layer 4 Protocol</p>;
}