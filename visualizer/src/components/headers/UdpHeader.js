import React, { useState } from "react";
import "./ip.css";
import HexDump from '../hex-dump/HexDump';


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

              <table className="table table-bordered table-sm udp-table" style={{ fontSize: "14px" }}>
                <tbody>

                  <tr>
                    <th colSpan="2" style={{textAlign: "Center"}}>
                      <b>UDP Header</b>
                    </th>
                  </tr>

                  <tr>
                    <th>Source Port</th>
                    <td> {udp.str_src_port} [{udp.src_port}] </td>
                  </tr>

                  <tr>
                    <th>Destination Port</th>
                    <td> {udp.str_dst_port} [{udp.dst_port}] </td>
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

                  {udp.payload ? (
                    <>
                      <tr>
                        <th>Payload</th>
                        <td>
                          {udp.payload && udp.payload.length > 5 
                            ? udp.payload.slice(0, 5) + "..." 
                            : udp.payload}
                        </td>
                      </tr>
                    </>
                  ) : (
                    <></>
                  )}

                </tbody>
              </table>
            </div>

            <div style={{ flex: "1 1 auto", display: "flex", 
                flexDirection: "column", gap: "15px", minWidth: 0 }}>

              <div style={{ flex: "1 1 auto", overflowX: "auto" }}>
                <div style={{ fontWeight: "bold", marginBottom: "5px" }}>UDP Header</div>
                <HexDump raw={udp.raw} /> 
              </div>

              <div style={{ flex: "1 1 auto", overflowX: "auto" }}>
                {udp.payload ? (
                  <>
                    <div style={{ fontWeight: "bold", marginBottom: "5px" }}>Payload ( {udp.payload.length} bytes )</div>
                    <HexDump raw={udp.payload} /> 
                  </>
                ) : (
                  <></>
                )}
              </div>
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
                <td colSpan="16"><i>Source Port:</i> {udp.str_src_port} [{udp.src_port}] </td>
                <td colSpan="16"><i>Destination Port:</i> {udp.str_dst_port} [{udp.dst_port}] </td>
              </tr>

              <tr>
                <th>32</th>
                <td colSpan="16"><i>Length:</i> {udp.length}</td>
                <td colSpan="16"><i>Checksum:0x</i>
                  {/* {udp.checksum} */}
                  {udp.checksum != null ? udp.checksum.toString(16).toUpperCase().padStart(4, "0") : "-"}
                </td>
              </tr>

              {udp.payload ? (
                <>
                  <tr>
                    <th>128</th>
                    <td colSpan="32"><i>Payload..</i> 
                    </td>
                  </tr>
                </>
              ) : (
                <></>
              )}

            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}