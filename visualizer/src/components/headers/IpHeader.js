import React, { useState, useMemo } from "react";
import HexDump from '../hex-dump/HexDump';
import BitGridHeader from './gtp/BitGridHeader'; // 방금 만든 파일 임포트
import "./IpHeader.css";

// 헬퍼 함수: 16진수 변환 및 포맷팅
const toHex = (val) => (val != null ? `0x${val.toString(16).toUpperCase()}` : "-");

const IpHeader = ({ ip, depth }) => {
  const [viewMode, setViewMode] = useState("decoded"); // "decoded" | "raw"

  if (!ip) return null;

  const isRaw = viewMode === "raw";

  return (
    <div className={`protocol-card ip-card ${depth > 0 ? 'inner-header' : ''}`}>
      {/* Header Section */}
      <div className="protocol-card__header">
        <div className="d-flex align-items-center">
          <span className="protocol-badge">L3</span>
          <strong className="protocol-title">
            IPv4 Header {depth > 0 && <span className="depth-tag">Inner #{depth}</span>}
          </strong>
        </div>
        
        <div className="view-selector">
          {/* <span className={`view-label ${!isRaw ? 'active' : ''}`}>Decoded</span> */}
        <div className="form-check form-switch d-inline-flex align-items-center ms-3" style={{ fontSize: "14px" }} >

          <label className="form-check-label me-5" htmlFor="gtpSwitch">
            {isRaw ? "Raw" : "Decoded"}
          </label>

          {/* <div className="form-check form-switch mx-2"> */}
            <input 
              className="form-check-input " 
              id="gtpSwitch"
              type="checkbox" 
              role="switch" 
              checked={isRaw}
              onChange={() => setViewMode(isRaw ? "decoded" : "raw")} 
            />
          </div>
          {/* <span className={`view-label ${isRaw ? 'active' : ''}`}>Raw</span> */}
        </div>
      </div>

      <div className="protocol-card__body">
        {isRaw ? (
          <div className="raw-view-container">
            <div className="summary-table-wrapper">
              <table className="table-summary">
                <thead>
                  <tr><th colSpan="2">Header Fields Summary</th></tr>
                </thead>
                <tbody>
                  <tr><th>Version / IHL</th><td>{ip.version} / {ip.ihl}</td></tr>
                  <tr><th>DSCP / ECN</th><td>{ip.dscp} / {ip.ecn}</td></tr>
                  <tr><th>Total Length</th><td>{ip.total_length} bytes</td></tr>
                  <tr><th>Identification</th><td>{toHex(ip.id)} ({ip.id})</td></tr>
                  <tr><th>Flags</th><td>{ip.flags === 2 ? "DF" : ip.flags === 1 ? "MF" : "None"}</td></tr>
                  <tr><th>Fragment Offset</th><td>{ip.fragment_offset}</td></tr>
                  <tr><th>TTL / Protocol</th><td>{ip.ttl} / {ip.next} ({ip.protocol})</td></tr>
                  <tr><th>Checksum</th><td>{toHex(ip.checksum)}</td></tr>
                  <tr className="highlight"><th>Source</th><td>{ip.src_addr}</td></tr>
                  <tr className="highlight"><th>Destination</th><td>{ip.dst_addr}</td></tr>
                </tbody>
              </table>
            </div>
            <div className="hexdump-wrapper">
              <HexDump raw={ip.raw} />
            </div>
          </div>
        ) : (
          <div className="decoded-view-container">
            <table className="bit-grid-table">
              <BitGridHeader showOctet={true}/>
              {/* <thead>
                <tr className="octet-indices">
                  <th>Oct</th>
                  <th colSpan="8">0</th>
                  <th colSpan="8">1</th>
                  <th colSpan="8">2</th>
                  <th colSpan="8">3</th>
                </tr>
                <tr className="bit-indices">
                  <th>Bit</th>
                  {[...Array(32)].map((_, i) => (
                  <th key={i} style={{ minWidth: "11px" }}>{i}</th>
                  ))}
                </tr>
              </thead> */}
              <tbody>
                <tr>
                  <th>0</th>
                  <td colSpan="4" className="field">Ver: {ip.version}</td>
                  <td colSpan="4" className="field">IHL: {ip.ihl}</td>
                  <td colSpan="6" className="field">DSCP: {ip.dscp}</td>
                  <td colSpan="2" className="field">ECN: {ip.ecn}</td>
                  <td colSpan="16" className="field highlight-field">Total Length: {ip.total_length}</td>
                </tr>
                <tr>
                  <th>4</th>
                  <td colSpan="16" className="field">Identification: {toHex(ip.id)}</td>
                  <td colSpan="3" className="field">Flags: {ip.flags}</td>
                  <td colSpan="13" className="field">Frag Offset: {ip.fragment_offset}</td>
                </tr>
                <tr>
                  <th>8</th>
                  <td colSpan="8" className="field">TTL: {ip.ttl}</td>
                  <td colSpan="8" className="field">Protocol: {ip.protocol}</td>
                  <td colSpan="16" className="field">Checksum: {toHex(ip.checksum)}</td>
                </tr>
                <tr>
                  <th>12</th>
                  <td colSpan="32" className="field address-field">Source Address: {ip.src_addr}</td>
                </tr>
                <tr>
                  <th>16</th>
                  <td colSpan="32" className="field address-field">Destination Address: {ip.dst_addr}</td>
                </tr>
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default IpHeader;