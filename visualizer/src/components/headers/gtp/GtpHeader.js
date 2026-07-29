import React, { useState, useRef, useEffect } from "react";
import BitGridHeader from '../common/BitGridHeader';
import HexDump from '../common/HexDump';
import GtpIeViewer from './GtpIeViewer';
import GtpIeTable from './GtpIeTable';
import "./GtpViewer.css";

function decodeBearerQoS(bytes, detail)
{
  if (!bytes || bytes.length < 2) {
    return "Invalid bytes"+(bytes.length);
  }

  let offset = 0;

  // 1바이트: PCI/PL/PVI
  const pci = (bytes[offset] & 0x40) !== 0;
  const pl = (bytes[offset] & 0x3c) >> 2;
  const pvi = (bytes[offset] & 0x01) !== 0;
  offset += 1;

  // 1바이트: QCI
  const qci = bytes[offset++];

  // 5바이트 숫자 → Number로 계산 (40bit까지 안전)
  function read5BytesNumber(start) {
    if (bytes.length < start + 5) return 0;
    return (
      (bytes[start] << 32) +
      (bytes[start + 1] << 24) +
      (bytes[start + 2] << 16) +
      (bytes[start + 3] << 8) +
      bytes[start + 4]
    );
  }

  const maxBitRateUL = read5BytesNumber(offset);
  offset += 5;

  const maxBitRateDL = read5BytesNumber(offset);
  offset += 5;

  const gbrUL = read5BytesNumber(offset);
  const gbrDL = read5BytesNumber(offset + 5);

  if (detail) {
    return (<td colSpan="4" style={{textAlign:"center"}}> PCI: ${pci}</td>);
  }
  else {
    return [
      `PCI: ${pci}`,
      `PL: ${pl}`,
      `PVI: ${pvi}`,
      `QCI: ${qci}`,
      `Max Bit Rate UL: ${maxBitRateUL} kbps`,
      `Max Bit Rate DL: ${maxBitRateDL} kbps`,
      `GBR UL: ${gbrUL} kbps`,
      `GBR DL: ${gbrDL} kbps`
    ].join("\n");
  }
}


function decodeEBI(bytes) {
  if (!bytes || bytes.length < 1) return "(empty)";
  return bytes[0] & 0x0f;   // lower 4 bits
}

function formatFTEID(f) {
  return [
    `V4: ${f.v4}`,
    `V6: ${f.v6}`,
    `Iface: ${f.iface_type}`,
    `TEID: ${f.teid}`,
    `IPv4: ${f.ipv4 ?? "none"}`,
    `IPv6: ${f.ipv6 ?? "none"}`
  ].join("\n");
}

function decodeAMBR(bytes) {
  let offset = 0;

  let uplink = 
    (((bytes[offset] << 24) |
    (bytes[offset+1] << 16) |
    (bytes[offset+2] << 8)  |
    bytes[offset+3] ) >>> 0);
  offset += 4;

  let downlink = 
    (((bytes[offset] << 24) |
    (bytes[offset+1] << 16) |
    (bytes[offset+2] << 8)  |
    bytes[offset+3] ) >>> 0);

    return [
      `AMBR Uplink: ${uplink}`,
      `AMBR Downlink: ${downlink}`
    ].join("\n");

}

function decodeFTEID(bytes) {
  let offset = 0;
  if (!bytes || bytes.length < 5) {
    throw new Error("F-TEID IE too short");
  }

  let v4 = (bytes[offset]&0x80) !== 0;
  let v6 = (bytes[offset]&0x40) !== 0;
  let iface_type = (bytes[offset]&0x3f);
  offset += 1;

  let teid = 
    (bytes[offset] << 24) |
    (bytes[offset+1] << 16) |
    (bytes[offset+2] << 8)  |
    (bytes[offset+3] );

  offset += 4;
  let ipv4 = null;
  let ipv6 = null;

  if (v4) {
    ipv4 = `${bytes[offset++]}.${bytes[offset++]}.${bytes[offset++]}.${bytes[offset++]}`;

  }
  if (v6) {
    const arr = bytes.slice(offset, offset + 16);
    offset += 16;

    // Convert to IPv6 string
    ipv6 = Array.from(new Uint8Array(arr))
      .map((b, i) => (i % 2 === 0 ? (b << 8) | arr[i + 1] : null))
      .filter(v => v !== null)
      .map(v => v.toString(16))
      .join(":");
  }

  return {
    v4,
    v6,
    iface_type,
    teid: teid >>> 0,  // unsigned
    ipv4,
    ipv6
  };

}

function decodeAPN(bytes) {
  if (!bytes || bytes.length === 0) return "(empty)";

  // bytes → 문자열
  return bytes.map(b => String.fromCharCode(b)).join("");
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// IMSI BCD decode
function decodeBCD(input) {
  let bytes;

  // hex string이 들어온 경우
  if (typeof input === "string") {
    bytes = hexToBytes(input);
  } 
  // Uint8Array가 들어온 경우
  else {
    bytes = input;
  }

  let digits = [];

  for (let b of bytes) {
    const low = b & 0x0f;
    const high = (b & 0xf0) >> 4;

    if (low <= 9) digits.push(low);
    // high nibble가 0xF이면 끝을 의미하므로 break
    if (high <= 9) digits.push(high);
  }

  return digits.join("");
}


function renderIeGrid(ie_value) {

  // 1. 데이터가 없거나 undefined인 경우 방어
  if (ie_value === null || ie_value === undefined) return null;

  // 2. ✨ 핵심 수정: 어떤 타입이 들어오든 문자열로 변환
  // 숫자가 들어오면 "123"으로, 객체면 JSON 문자열로 바꿉니다.
  const safeValue = typeof ie_value === 'string' 
    ? ie_value 
    : String(ie_value);

  const charsPerRow = 8; // 4바이트 = 8글자 (Hex 기준)
  
  // 1️⃣ 데이터를 8글자씩 쪼개서 chunks 배열 생성
  const chunks = [];
  // for (let i = 0; i < ie_value.length; i += charsPerRow) {
  //   chunks.push(ie_value.substring(i, i + charsPerRow));
  // }
const totalRows = Math.ceil(safeValue.length / charsPerRow);
  return (
    <>
      {chunks.map((chunk, rowIdx) => (
        <tr key={rowIdx}>
          {/* 💡 핵심: 이전 th(IE 이름 칸)에서 이미 rowSpan을 줬으므로 
            여기서는 데이터 칸(32비트 너비)만 채우면 됩니다.
          */}
          <td 
            colSpan="32" // 부모 테이블의 전체 비트 너비에 맞춤
            className="text-center font-monospace"
            style={{ 
              backgroundColor: '#ffffff', 
              padding: '8px', 
              border: '1px solid #eee',
              letterSpacing: '2px' // 글자 사이 간격을 벌려 가독성 확보
            }}
          >
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: `repeat(${charsPerRow}, 1fr)`,
              gap: '2px'
            }}>
              {/* 2️⃣ 각 글자를 개별 칸에 넣어 격자 느낌 극대화 */}
              {chunk.split('').map((char, charIdx) => (
                <span key={charIdx} style={{ borderRight: charIdx % 2 === 1 ? '1px solid #ddd' : 'none' }}>
                  {char}
                </span>
              ))}
              
              {/* 3️⃣ 4바이트가 안 채워졌을 때 Spare 표시 */}
              {chunk.length < charsPerRow && (
                <div 
                  style={{ gridColumn: `span ${charsPerRow - chunk.length}`, color: '#ccc', fontSize: '10px' }}
                  className="bg-light"
                >
                  (Spare)
                </div>
              )}
            </div>
          </td>
        </tr>
      ))}
    </>
  );
}



const IeRow = ({ label, value, bitSpan = 32 }) => (
  <tr>
    <th style={{ width: '120px', backgroundColor: '#f8f9fa', color: '#666', fontWeight: 'normal', border: '1px solid #dee2e6' }}>
      {label}
    </th>

    <td colSpan={bitSpan} style={{ border: '1px solid #dee2e6', fontFamily: 'monospace' }}>
      {value}
    </td>
  </tr>
);






export default function GtpHeader({ gtp }) {
  const [viewMode, setViewMode] = useState("decoded");
  const [hoveredRaw, setHoveredRaw] = useState(null); // ★ hover 상태
  const [hoverTop, setHoverTop] = useState(0);  // 두 번째 HexDump top
  const fullHexRef = useRef();

  useEffect(() => {

    if (fullHexRef.current) {
      setHoverTop(fullHexRef.current.offsetHeight + 12); // 12px gap
    }
  }, [viewMode, gtp.raw]); // 메시지가 바뀌면 갱신

  if (!gtp) return null;

  return (
    <div className="card mb-3">
      <div className="card-header gtp-header d-flex justify-content-between align-items-center">
        <div className="d-flex align-items-center">
          <span className="protocol-badge">L7</span>
        <strong>GTPv2-C</strong>
        </div>

        <div className="form-check form-switch d-inline-flex align-items-center ms-3"
          style={{ fontSize: "14px" }} >

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

      <div className="card-body gtp-card-body">
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
                    <th>Version</th>
                    <td>{gtp.version}</td>
                  </tr>
                  <tr>
                    <th>P Flag</th>
                    <td> {gtp.p_flag ? "1" : "0"} </td>
                  </tr>
                  <tr>
                    <th>T Flag</th>
                    <td> {gtp.p_flag ? "1" : "0"} </td>
                  </tr>

                  <tr>
                    <th>MP Flag</th>
                    <td> {gtp.mp_flag ? "1" : "0"} </td>
                  </tr>

                  <tr>
                    <th>Message Type</th>
                    <td>
                      {gtp.msg_type_str} [{gtp.msg_type}]
                    </td>
                  </tr>
                  <tr>
                    <th>Message Length</th>
                    <td>
                      {gtp.msg_len}
                    </td>
                  </tr>

                  { gtp.t_flag ? (
                    <tr>
                      <th>TEID</th>
                      <td>
                        0x{gtp.teid != null ? gtp.teid.toString(16)
                          .padStart(8, "0") : "-"}
                      </td>
                    </tr>
                  ):null} 

                  <tr>
                    <th>Sequence</th>
                    <td>
                      0x{gtp.seq != null ? gtp.seq.toString(16).padStart(8, "0") : "-"}
                    </td>
                  </tr>

                  <tr >
                    <td colSpan="2" style={{backgroundColor:"#a3b2c3"}}>
                      GTP IEs
                      <GtpIeViewer ies={gtp.ies} onHoverRaw={setHoveredRaw} />  {/* 여기서 호출 */}
                    </td>
                  </tr>

                </tbody>
              </table>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "12px", flex: "0 0 400px" }}>
    
              {/* 전체 GTP HexDump */}
              <div 
                ref={fullHexRef}
                style={{
                  position: "sticky",
                  top: "10px",
                  height: "fit-content",
                  overflowX: "auto",
                  overflowY: "auto",
                  background: "#111a23",
                  borderRadius: "10px",
                  padding: "8px"
                }} >
                <HexDump raw={gtp.raw} />
              </div>

              {/* Hovered IE HexDump */}
              <div
                style={{
                  position: "sticky",
                  top: `${hoverTop}px`, 
                  // maxHeight: "400px",
                  height: "fit-content",
                  overflowX: "auto",
                  overflowY: "auto",
                  background: "#1b1f27",
                  borderRadius: "10px",
                  padding: "8px"
                }}
              >
                {hoveredRaw ? <HexDump raw={hoveredRaw} /> : <div style={{ color: "#888" }}>Hover an IE to see raw data</div>}
              </div>
            </div>
          </div>

        ) : (

          <div>
            {/* <table className="gtp-table "> */}
            <table className="bit-grid-table ">

              <BitGridHeader showOctet={true}/>

              <tbody>
                <tr>
                  <th rowSpan="3" colSpan="2" className="vertical gtp-header">
                    GTP Header
                  </th>
                  <td colSpan="3" className="field"><i>Version:</i> {gtp.version}</td>
                  <td colSpan="1" className="field"><i>P:</i>
                    {gtp.p_flag ? "1" : "0"}
                  </td>
                  <td colSpan="1" className="field"><i>T:</i> {gtp.t_flag ? "1" : "0"}</td>
                  <td colSpan="1" className="field"><i>MP:</i> {gtp.mp_flag ? "1" : "0"}</td>
                  <td colSpan="2" className="field"><i>Reserved</i> </td>

                  <td colSpan="8" className="field"><i>Message Type:</i>{gtp.msg_type_str} [{gtp.msg_type}] </td>
                  <td colSpan="16" className="field"><i>Message Length:</i>{gtp.msg_len} </td>
                </tr>

                <tr>
                  { gtp.t_flag ? (
                    <td colSpan="32" className="field"><i>TEID:0x</i>
                      {gtp.teid != null ? gtp.teid.toString(16)
                      // .toUpperCase()
                      .padStart(8, "0") : "-"}
                      {/* {gtp.teid} */}
                    </td>
                  ) : (
                    <>
                      <td colSpan="24" className="field"><i>Sequence Number:0x</i>
                        {gtp.seq != null ? gtp.seq.toString(16).padStart(8, "0")
                        // .toUpperCase()
                        : "-"}
                        {/* {gtp.seq} */}
                      </td>
                      {/* <td colSpan="8"><i>Sequence Number</i> </td> */}
                      <td colSpan="8" className="field"><i>Spare</i> </td>
                    </>
                  )}
                </tr>

                <tr>
                  { gtp.t_flag ? (
                    <>
                    <td colSpan="24" className="field"><i>Sequence Number:0x</i>
                        {gtp.seq != null ? gtp.seq.toString(16)
                          .padStart(6, "0") : "-"}
                    </td>
                    <td colSpan="8" className="field"><i>Spare</i> </td>
                    </>
                  ):(<></>)}
                </tr>

                <GtpIeTable ies={gtp.ies} />

              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}