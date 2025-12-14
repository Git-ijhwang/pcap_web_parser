import React, { useState } from "react";
import "./ip.css";
import HexDump from '../hex-dump/HexDump';


export default function Ipv6Header({ ip, depth }) {
  const [viewMode, setViewMode] = useState("decoded");

  if (!ip) return null;

  return (
    <div className="card mb-3">
      <div className="card-header ip-header d-flex justify-content-between align-items-center">

        <strong>Layer 3 (IPv6)</strong>
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
                      <b>IPv6 Header</b>
                    </th>
                  </tr>

                  <tr>
                    <th>Version</th>
                    <td>{ip.version}</td>
                  </tr>

                  <tr>
                    <th>Traffic Class</th>
                    <td>{ip.tc}</td>
                  </tr>

                  <tr>
                    <th>Flow Label</th>
                    <td>{ip.fl}</td>
                  </tr>

                  <tr>
                    <th>Playload Length</th>
                    <td>{ip.pl} bytes</td>
                  </tr>

                  <tr>
                    <th>Next Header</th>
                    <td>{ip.next} bytes</td>
                  </tr>

                  <tr>
                    <th>Hop Limit</th>
                    <td>{ip.hop} bytes</td>
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
              <HexDump raw={ip.raw} />
            </div>
          </div>
        ) : (
          <table className="ip-table ">
            <tbody>
              <tr>
                <th colSpan="33" style={{ textAlign: "center"}} >
                  <b>IPv6 Header</b>
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
                <td colSpan="8"><i>Traffic Class:</i> {ip.tc ?? "-"}</td>
                <td colSpan="20"><i>Payload Length:</i> {ip.pl ?? "-"}</td>
              </tr>

              {/* Row 4 */}
              <tr>
                <th>32</th>
                <td colSpan="16"><i>Payload Length:</i> {ip.pl}</td>
                <td colSpan="8"><i>Next Header:</i> {ip.next ?? "-"}</td>
                <td colSpan="8"><i>Hop Limit:</i> {ip.hop ?? "-"}</td>
              </tr>

              {/* Row 8 */}
              <tr>
                <th>64</th>
                <td colSpan="32" rowSpan="4"><i>Source Address:</i> {ip.src_addr ?? "-"}</td>
              </tr>

              <tr>
                <th>96</th>
              </tr>
              <tr>
                <th>128</th>
              </tr>
              <tr>
                <th>160</th>
              </tr>

              <tr>
                <th>192</th>
                <td colSpan="32" rowSpan="4"><i>Destination Address:</i> {ip.dst_addr ?? "-"}</td>
              </tr>

              <tr>
                <th>224</th>
              </tr>
              <tr>
                <th>256</th>
              </tr>
              <tr>
                <th>288</th>
              </tr>
            </tbody>
          </table>
        )}

      </div>
    </div>
  );
}