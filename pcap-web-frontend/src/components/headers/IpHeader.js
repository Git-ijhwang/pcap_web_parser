import React, { useState } from "react";
import "./ip.css";

function IpHexDump({ raw }) {
  if (!raw || raw.length === 0) return <div>No raw data</div>;

  const toHex = (n) => n.toString(16).padStart(2, "0").toUpperCase();
  const toAscii = (n) =>
    n >= 0x20 && n <= 0x7E ? String.fromCharCode(n) : ".";

  // 16 bytes per line
  const lines = [];
  for (let i = 0; i < raw.length; i += 16) {
    const chunk = raw.slice(i, i + 16);

    const offset = i.toString(16).padStart(4, "0");

    const first8 = chunk.slice(0, 8).map(toHex).join(" ");
    const last8 = chunk.slice(8, 16).map(toHex).join(" ");
    const hexBytes = first8 + "  " + last8; // 두 그룹 사이에 여분의 공백

    const ascii = chunk
      .map((b) => toAscii(b))
      .join("");

    lines.push({ offset, hexBytes, ascii });
  }

  return (
    <pre
      style={{
        background: "#111a23ff",
        color: "#eee",
        padding: "10px",
        borderRadius: "6px",
        fontFamily: "monospace",
        fontSize: "13px",
        overflowX: "auto"
      }}
    >
      {lines.map((line, idx) => (
        <div key={idx}>
          {line.offset}  {line.hexBytes.padEnd(47)}  {line.ascii}
        </div>
      ))}
    </pre>
  );
}


export default function IpHeader({ ip }) {
  const [viewMode, setViewMode] = useState("decoded");

  if (!ip) return null;

  return (
    <div className="card mb-3">
      <div className="card-header ip-header d-flex justify-content-between align-items-center">
        <strong>Layer 3 (IP)</strong>
        <div className="form-check form-switch d-inline-flex align-items-center ms-3" style={{ fontSize: "14px" }} >

          <label className="form-check-label me-5" htmlFor="gtpSwitch">
            {viewMode === "raw" ? "Raw" : "Decoded"}
          </label>

          <input className="form-check-input" type="checkbox" role="switch" id="gtpSwitch" checked={viewMode === "raw"}
              onChange={() => setViewMode(viewMode === "raw" ? "decoded" : "raw") } />
        </div>

      </div>

      <div className="card-body ip-card-body">

        {viewMode === "raw" ? (

          <div style={{ display: "flex", gap: "15px" }}>
            <div style={{ flex: "0 0 600px" }}>

              <table className="table table-bordered table-sm" style={{ fontSize: "14px" }}>
                <tbody>

                  <tr>
                    <th colSpan="2" style={{textAlign: "Center"}}>
                      <b>IP Header</b>
                    </th>
                  </tr>

                  <tr>
                    <th>Version</th>
                    <td>{ip.version}</td>
                  </tr>

                  <tr>
                    <th>IHL</th>
                    <td>{ip.ihl}</td>
                  </tr>

                  <tr>
                    <th>DSCP</th>
                    <td>{ip.dscp}</td>
                  </tr>

                  <tr>
                    <th>ECN</th>
                    <td>{ip.ecn}</td>
                  </tr>

                  <tr>
                    <th>Total Length</th>
                    <td>{ip.total_length}</td>
                  </tr>

                  <tr>
                    <th>ID</th>
                    <td>{ip.id}</td>
                  </tr>

                  <tr>
                    <th>Flags</th>
                    <td>
                      {ip.flags === 2 ? "DF (Don't Fragment)" : ip.flags === 1 ? "MF (More Fragment)" : "-"}
                    </td>
                  </tr>

                  <tr>
                    <th>Fragment Offset</th>
                    <td>{ip.fragment_offset}</td>
                  </tr>

                  <tr>
                    <th>TTL</th>
                    <td>{ip.ttl}</td>
                  </tr>

                  <tr>
                    <th>Protocol</th>
                    <td>
                      {ip.next} [{ip.protocol}]
                    </td>
                  </tr>

                  <tr>
                    <th>Checksum</th>
                    <td>
                      0x{ip.checksum != null ? ip.checksum.toString(16).toUpperCase() : "-"}
                    </td>
                  </tr>

                  <tr>
                    <th>Source Address</th>
                    <td>{ip.src_addr}</td>
                  </tr>

                  <tr>
                    <th>Destination Address</th>
                    <td>{ip.dst_addr}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div style={{ flex: "1 1 auto", overflowX: "auto" }}>
                    <IpHexDump raw={ip.raw} />
            </div>
          </div>
        ) : (
          <table className="ip-table ">
            <tbody>
              <tr>
                <th colSpan="33" style={{ textAlign: "center"}} >
                  <b>IP Header</b>
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

              {/* Bit index row */}
              <tr>
                <th style={{ minWidth: "42px" }}>Bit</th>
                {[...Array(32)].map((_, i) => (
                  <th key={i} style={{ minWidth: "11px" }}>{i}</th>
                ))}
              </tr>

              {/* Row 0 */}
              <tr>
                <th>0</th>
                <td colSpan="4"><i>Version:</i> {ip.version ?? "-"}</td>
                <td colSpan="4"><i>IHL:</i> {ip.ihl ?? "-"}</td>
                <td colSpan="6"><i>DSCP:</i> {ip.dscp}</td>
                <td colSpan="2"><i>ECN:</i> {ip.ecn}</td>
                <td colSpan="16"><i>Total Length:</i> {ip.total_length}</td>
              </tr>

              {/* Row 4 */}
              <tr>
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
                <td colSpan="8"><i>Protocol:</i> {ip.protocol} ({ip.next})</td>
                <td colSpan="16"><i>Header Checksum:0x</i>
                  {/* {ip.checksum} */}
                  {ip.checksum != null ? ip.checksum.toString(16).toUpperCase() : "-"}
                </td>
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
        )}
      </div>
    </div>
  );
}