import React from "react";
import "./ip.css";


export default function IpHeader({ ip }) {
    if (!ip) return null;
  return (
<table className="ip-table">
      <tbody>
        {/* Header Row */}
        <tr>
          {/* <th style={{ minWidth: "42px", borderBottom: "none", borderRight: "none" }}><i>Offset</i></th> */}
          <th style={{ borderLeft: "" }}>Octet</th>
          <th colSpan="8">0</th>
          <th colSpan="8">1</th>
          <th colSpan="8">2</th>
          <th colSpan="8">3</th>
        </tr>

        {/* Bit index row */}
        <tr>
          {/* <th style={{ minWidth: "42px", borderTop: "none" }}>Octet</th> */}
          <th style={{ minWidth: "42px" }}>Bit</th>
          {[...Array(32)].map((_, i) => (
            <th key={i} style={{ minWidth: "11px" }}>{i}</th>
          ))}
        </tr>

        {/* Row 0 */}
        <tr>
          {/* <th>0</th> */}
          <th>0</th>
          <td colSpan="4"><i>Version:</i> {ip.version ?? "-"}</td>
          <td colSpan="4"><i>IHL:</i> {ip.ihl ?? "-"}</td>
          <td colSpan="6"><i>DSCP:</i> {ip.dscp}</td>
          <td colSpan="2"><i>ECN:</i> {ip.ecn}</td>
          <td colSpan="16"><i>Total Length:</i> {ip.total_length}</td>
        </tr>

        {/* Row 4 */}
        <tr>
          {/* <th>4</th> */}
          <th>32</th>
          <td colSpan="16"><i>Identification:</i> {ip.id}</td>
          <td colSpan="3"><i>Flags:</i> {" "}
  {ip.flags === 2 ? "DF" :
   ip.flags === 1 ? ", MF" :
   "0"}
          </td>
          <td colSpan="13"><i>Fragment Offset:</i> {ip.fragment_offset}</td>
        </tr>

        {/* Row 8 */}
        <tr>
          {/* <th>8</th> */}
          <th>64</th>
          <td colSpan="8"><i>TTL:</i> {ip.ttl}</td>
          <td colSpan="8"><i>Protocol:</i> {ip.protocol}</td>
          <td colSpan="16"><i>Header Checksum:</i> {ip.checksum}</td>
        </tr>

        {/* Row 12 */}
        <tr>
          {/* <th>12</th> */}
          <th>96</th>
          <td colSpan="32"><i>Source Address:</i> {ip.src_addr}</td>
        </tr>

        {/* Row 16 */}
        <tr>
          {/* <th>16</th> */}
          <th>128</th>
          <td colSpan="32"><i>Destination Address:</i> {ip.dst_addr}</td>
        </tr>
      </tbody>
    </table>
  );
}