import React, { useState } from "react";
import "./ip.css";
import HexDump from '../hex-dump/HexDump';


export default function IcmpHeader({ icmp }) {
  const [viewMode, setViewMode] = useState("decoded");

  if (!icmp) return null;

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
                      <b>ICMP Header</b>
                    </th>
                  </tr>

                  <tr>
                    <th>ICMP Type</th>
                    <td> {icmp.icmp_type} [{icmp.icmp_type}] </td>
                  </tr>

                  <tr>
                    <th>ICMP Code</th>
                    <td> {icmp.code} </td>
                  </tr>

                  <tr>
                    <th>ID</th>
                    <td>{icmp.id}</td>
                  </tr>

                  <tr>
                    <th>Sequence</th>
                    <td>{icmp.seq}</td>
                  </tr>


                </tbody>
              </table>
            </div>

            <div style={{ flex: "1 1 auto", overflowX: "auto" }}>
              <HexDump raw={icmp.raw} /> 
            </div>

          </div>

        ) : (
          <table className="ip-table ">
            <tbody>
              <tr>
                <th colSpan="33" style={{ textAlign: "center" }}>
                  <b>ICMP Header</b>
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
                <td colSpan="8"><i>Type: </i> {icmp.icmp_type} [{icmp.icmp_type}] </td>
                <td colSpan="8"><i>Code: </i> {icmp.code} </td>
                <td colSpan="16"><i>Checksum: </i> {icmp.checksum} </td>
              </tr>

              <tr>
                <th>32</th>
                <td colSpan="16"><i>Id: 0x</i>
                  {icmp.id != null ? icmp.id.toString(16).toUpperCase().padStart(4, "0") : "-"}
                </td>
                <td colSpan="16"><i>Seq: 0x</i>
                  {icmp.checksum != null ? icmp.checksum.toString(16).toUpperCase().padStart(4, "0") : "-"}
                </td>
              </tr>
            </tbody>
          </table>
        )}
      </div>

    </div>
  );
}