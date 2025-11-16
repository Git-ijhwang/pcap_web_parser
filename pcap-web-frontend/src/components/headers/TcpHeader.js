import React from "react";

export default function TcpHeader({ tcp }) {
    if (!tcp) return null;
  return (
      <div className="card mb-3">
        <div className="card-header">
          <strong>Layer 4 (Transport)</strong>
        </div>
        <div className="card-body">
     <table className="ip-table">
      <tbody>
        <tr>
          <th colSpan="33" style={{ textAlign: "center" }}>
            <b>TCP Header</b>
          </th>
        </tr>

        <tr>
          <th>Bit</th>
          {[...Array(32)].map((_, i) => (
            <th key={i}>{i}</th>
          ))}
        </tr>

        <tr>
          <th>0</th>
          <td colSpan="16"><i>Source Port:</i> {tcp.src_port}</td>
          <td colSpan="16"><i>Destination Port:</i> {tcp.dst_port}</td>
        </tr>

        <tr>
          <th>32</th>
          <td colSpan="32"><i>Sequence Number:</i> {tcp.seq}</td>
        </tr>

        <tr>
          <th>32</th>
          <td colSpan="32"><i>Acknowledge Number:</i> {tcp.ack}</td>
        </tr>

        <tr>
          <th>64</th>
          <td colSpan="4"><i>Header Size:</i> {tcp.ack}</td>
          <td colSpan="4"><i>Reserved</i></td>
          <td colSpan="8"><i></i>{" "}
            {
            tcp.flags & 0x1 ? "FIN " :
            tcp.flags & 0x2 ? "SYN " :
            tcp.flags & 0x4 ? "RST " :
            tcp.flags & 0x8 ? "PSH " :

            tcp.flags & 0x16 ? "ACK " :
            tcp.flags & 0x32 ? "URG " :
            tcp.flags & 0x64 ? "ECE " :
            tcp.flags & 0x128 ? "CWR " : "0"
            }
          </td>
          <td colSpan="8"><i>Window:</i> {tcp.window}</td>
        </tr>

        <tr>
          <th>96</th>
          <td colSpan="16"><i>Checksum:</i> 
            {/* {tcp.ack} */}
            {tcp.ack != null ? tcp.checksum.toString(16).toUpperCase(): "-"}
            </td>
          <td colSpan="16"><i>Urgent Point:</i> 
          {tcp.urgent}
            </td>
        </tr>

      </tbody>
    </table>
    </div>
    </div>
  );
}