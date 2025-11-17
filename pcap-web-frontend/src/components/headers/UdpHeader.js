import React from "react";
import "./ip.css";

export default function UdpHeader({ udp }) {
  if (!udp) return null;
  return (
    <div className="card mb-3">
      <div className="card-header udp-header">
        <strong>Layer 4 (Transport)</strong>
      </div>

      <div className="card-body udp-card-body">
        <table className="ip-table ">
          <tbody>
            <tr>
              <th colSpan="33" style={{ textAlign: "center" }}>
                <b>UDP Header</b>
              </th>
            </tr>

            {/* Header Row */}
            <tr>
              <th style={{ borderLeft: "" }}>Octet</th>
              <th colSpan="8">0</th>
              <th colSpan="8">1</th>
              <th colSpan="8">2</th>
              <th colSpan="8">3</th>
            </tr>

            <tr>
              <th>Bit</th>
              {[...Array(32)].map((_, i) => (
                <th key={i}>{i}</th>
              ))}
            </tr>

        <tr>
          <th>0</th>
          <td colSpan="16"><i>Source Port:</i> {udp.src_port}</td>
          <td colSpan="16"><i>Destination Port:</i> {udp.dst_port}</td>
        </tr>

        <tr>
          <th>32</th>
          <td colSpan="16"><i>Length:</i> {udp.length}</td>
          <td colSpan="16"><i>Checksum:0x</i>
            {/* {udp.checksum} */}
            {udp.checksum != null ? udp.checksum.toString(16).toUpperCase().padStart(4, "0") : "-"}
          </td>
        </tr>
      </tbody>
    </table>
    </div>
    </div>
  );
}