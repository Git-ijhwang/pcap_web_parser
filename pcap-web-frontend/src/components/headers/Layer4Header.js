import React from "react";
import UdpHeader from "./UdpHeader";
import TcpHeader from "./TcpHeader";

export default function Layer4Header({ l4 }) {
  if (l4.UDP) return <UdpHeader udp={l4.UDP} />;
  if (l4.TCP) return <TcpHeader tcp={l4.TCP} />;
  return <p>Unknown Layer 4 Protocol</p>;
}