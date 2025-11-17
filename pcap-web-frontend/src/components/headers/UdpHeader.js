import React, { useState } from "react";
import "./ip.css";

function UdpHexDump({ raw }) {
  if (!raw || raw.length === 0) return <div>No raw data</div>;

  const toHex = (n) => n.toString(16).padStart(2, "0").toUpperCase();
  const toAscii = (n) =>
    n >= 0x20 && n <= 0x7E ? String.fromCharCode(n) : ".";

  // 16 bytes per line
  const lines = [];
  for (let i = 0; i < raw.length; i += 16) {
    const chunk = raw.slice(i, i + 16);

    const offset = i.toString(16).padStart(4, "0");

    // 16바이트를 두 그룹으로 나누기
    const first8 = chunk.slice(0, 8).map(toHex).join(" ");
    const last8 = chunk.slice(8, 16).map(toHex).join(" ");
    const hexBytes = first8 + "  " + last8; // 두 그룹 사이에 여분의 공백

    // const hexBytes = chunk
    //   .map((b) => toHex(b))
    //   .join(" ");

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

export default function UdpHeader({ udp }) {
  const [viewMode, setViewMode] = useState("decoded");

  if (!udp) return null;

  return (
    <div className="card mb-3">
      <div className="card-header udp-header d-flex justify-content-between align-items-center">
        <strong>Layer 4 (Transport)</strong>
        <div className="form-check form-switch d-inline-flex align-items-center ms-3" style={{ fontSize: "14px" }} >

          <label className="form-check-label me-5" htmlFor="gtpSwitch">
            {viewMode === "raw" ? "Raw" : "Decoded"}
          </label>

          <input
            className="form-check-input"
            type="checkbox"
            role="switch"
            id="gtpSwitch"
            checked={viewMode === "raw"}
            onChange={() =>
              setViewMode(viewMode === "raw" ? "decoded" : "raw")
            }
          />
        </div>

      </div>

      <div className="card-body udp-card-body">
        {viewMode === "raw" ? (

          <div style={{ display: "flex", gap: "15px" }}>
            <div style={{ flex: "0 0 600px" }}>

              <table className="table table-bordered table-sm" style={{ fontSize: "14px" }}>
                <tbody>

                  <tr>
                    <th colSpan="2" style={{textAlign: "Center"}}>
                      <b>GTP Header</b>
                    </th>
                  </tr>

                  <tr>
                    <th>Source Port</th>
                    <td>{udp.src_port}</td>
                  </tr>

                  <tr>
                    <th>Destination Port</th>
                    <td>{udp.dst_port}</td>
                  </tr>

                  <tr>
                    <th>Length</th>
                    <td>{udp.length}</td>
                  </tr>

                  <tr>
                    <th>Checksum</th>
                    <td>
                      0x{udp.checksum != null ? udp.checksum.toString(16).toUpperCase().padStart(4, "0") : "-"}
                    </td>
                  </tr>

                </tbody>
              </table>
            </div>

            <div style={{ flex: "1 1 auto", overflowX: "auto" }}>
              <UdpHexDump raw={udp.raw} /> 
            </div>

          </div>
        ) : (
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
    )}
    </div>
    </div>
  );
}