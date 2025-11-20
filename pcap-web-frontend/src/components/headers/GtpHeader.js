// import React, { useState } from "react";
import React, { useState, useRef, useEffect } from "react";


import "./ip.css";


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
    return (<td calSpan="4" style={{textAlign:"center"}}> PCI: ${pci}</td>);
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

function GtpHexDump({ raw }) {
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
        background: "#111a23",
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

function GtpIeSimpleViewer({ ies }) {
  const [hoveredRaw, setHoveredRaw] = React.useState(null);
  return (
    <div>
       <GtpIeSimpleTable ies={ies} onHoverRaw={setHoveredRaw} />
    </div>
  );
}

function GtpIeViewer({ ies }) {
  return (
    <div>
      <GtpIeTable ies={ies} />
    </div>
  );
}

function renderIeValue(value) {
  if (!value) return "(none)";

  const type = Object.keys(value)[0];
  const data = value[type];

  switch (type) {
    case "Raw":
      return (
        <span>
          {/* 0x{value.data.map((b) => b.toString(16).padStart(2, "0")).join("")} */}
          0x{data.map(b => b.toString(16).padStart(2, "0")).join("")}
        </span>
      );

    case "Uint8":
    case "Uint16":
    case "Uint32":
      return <span>{data}</span>;

    case "Utf8String":
    case "Apn":
      return <span>{data}</span>;

    case "Ipv4":
    case "Ipv6":
      return <span>{data}</span>;

    case "Timer":
      return (
        <span>
          unit={data.unit}, value={data.value}
        </span>
      );

    case "Ambr":
      return (
        <div>
          <div>UL: {data.ul}</div>
          <div>DL: {data.dl}</div>
        </div>
      );

    case "UserLocationInfo": {
  // data = UliValue 구조체
  const uli = data;

  return (
    <div style={{ padding: "4px 0" }}>
      {uli.has_tai && uli.tai && (
        <div style={{ marginBottom: "6px" }}>
          <b>TAI</b><br />
          MCC: {uli.tai.mcc}<br />
          MNC: {uli.tai.mnc}<br />
          TAC: {uli.tai.tac}
        </div>
      )}

      {uli.has_ecgi && uli.ecgi && (
        <div style={{ marginBottom: "6px" }}>
          <b>ECGI</b><br />
          MCC: {uli.ecgi.mcc}<br />
          MNC: {uli.ecgi.mnc}<br />
          ECI: {uli.ecgi.eci}
        </div>
      )}

      {uli.has_lai && uli.lai && (
        <div style={{ marginBottom: "6px" }}>
          <b>LAI</b><br />
          MCC: {uli.lai.mcc}<br />
          MNC: {uli.lai.mnc}<br />
          LAC: {uli.lai.lac}
        </div>
      )}

      {uli.has_rai && uli.rai && (
        <div style={{ marginBottom: "6px" }}>
          <b>RAI</b><br />
          MCC: {uli.rai.mcc}<br />
          MNC: {uli.rai.mnc}<br />
          RAC: {uli.rai.rac}
        </div>
      )}

      {uli.has_sai && uli.sai && (
        <div style={{ marginBottom: "6px" }}>
          <b>SAI</b><br />
          MCC: {uli.sai.mcc}<br />
          MNC: {uli.sai.mnc}<br />
          SAC: {uli.sai.sac}
        </div>
      )}

      {uli.has_cgi && uli.cgi && (
        <div style={{ marginBottom: "6px" }}>
          <b>CGI</b><br />
          MCC: {uli.cgi.mcc}<br />
          MNC: {uli.cgi.mnc}<br />
          CI: {uli.cgi.ci}
        </div>
      )}

      {/* 아무것도 없으면 빈 값 표시 */}
      {!uli.has_tai &&
        !uli.has_ecgi &&
        !uli.has_lai &&
        !uli.has_rai &&
        !uli.has_sai &&
        !uli.has_cgi && <span>(empty ULI)</span>}
    </div>
  );
}


    case "FTeid":
      return (
        <div>
          <div>TEID: 0x{data.teid.toString(16)}</div>
          {data.v4 &&
            <div>IPv4 Address: {data.ipv4}</div>
          }
          {data.v6 &&
            <div>IPv6 Address: {data.ipv6}</div>
          }
          <div>Interface Type: {data.iface_type}</div>
        </div>
      );

    case "ServingNetwork":
      return (
        <div>
          <div>MCC: {data.mcc}</div>
          <div>MNC: {data.mnc}</div>
        </div>
      );

    case "BearerQoS":
      return (
        <div>
          <div>QCI: {data.qci}</div>
          <div>Max UL: {data.max_ul}</div>
          <div>Max DL: {data.max_dl}</div>
          <div>Guaranteed UL: {data.gbr_ul}</div>
          <div>Guaranteed DL: {data.gbr_dl}</div>
        </div>
      );

    case "UserLocationInfo":
      return (
        <div>
          <div>TAI: {data.tai}</div>
          <div>ECGI: {data.ecgi}</div>
          <div>RAI: {data.rai}</div>
        </div>
      );

    case "SubIeList":
      return (
        <div style={{ marginLeft: "8px", borderLeft: "2px solid #ccc", paddingLeft: "8px" }}>
          {data.map((sub, idx) => (
            <div key={idx} style={{ marginBottom: "6px" }}>
              <strong>{sub.type_str}</strong>
              <div>{renderIeValue(sub.ie_value)}</div>
            </div>
          ))}
        </div>
      );

    case "None":
      return <span>(none)</span>;

    default:
      return <span>(unknown type)</span>;
  }
}

// function IeViewer({ ies, onHoverRaw = () => {}  }) {
//   const [hoveredRaw, setHoveredRaw] = React.useState(null);

//   return (
//     <div style={{ display: "flex", gap: "12px" }}>
//       <div style={{ flex: 1 }}>
//         <GtpIeSimpleTable ies={ies} onHoverRaw={setHoveredRaw} />
//       </div>

//       <div 
//         style={{
//           width: "350px",
//           border: "1px solid #ccc",
//           padding: "8px",
//           fontFamily: "monospace",
//           fontSize: "13px",
//           background: "#fafafa",
//           position: "sticky",
//           top: "10px",
//           height: "fit-content"
//         }}
//       >
//         {hoveredRaw ? <GtpHexDump raw={hoveredRaw} /> : <div>Hover an IE…</div>}
//       </div>
//     </div>
//   );
// }

function IeViewer({ ies, onHoverRaw = () => {} }) {
  return (   // <- 최종 return
    <div>
      {ies.map((ie, idx) => {
        const subIes = ie.ie_value?.SubIeList;
        const isGrouped = Array.isArray(subIes) && subIes.length > 0;

        return (  // <- map 안에서 JSX를 반환
          <div
            key={`ie-${ie.ie_type}-${ie.instance}-${idx}`}
            onMouseEnter={() => onHoverRaw(ie.raw)}
            onMouseLeave={() => onHoverRaw(null)}
          >
            <GtpIeSimpleTable ies={[ie]} level={0} onHoverRaw={onHoverRaw} />
          </div>
        );
      })}
    </div>
  );
}



function GtpIeSimpleTable({ ies, level = 0,onHoverRaw= () => {} }) {
  const bgColor=[ "#0ff0f0", "#04f010ff", "#00e0e0" ];

  return (
    <>
    {ies.map((ie, idx) => {
      const subIes = ie.ie_value?.SubIeList;
      const isGrouped = Array.isArray(subIes) && subIes.length > 0;

      return (
        <div
            onMouseEnter={() => onHoverRaw(ie.raw)}   // ★★ Hover 시 raw 표시
            onMouseLeave={() => onHoverRaw(null)}  // ★★ Hover 벗어나면 clear
        >
          <table className="table table-bordered table-sm ie-table"
                key={`ie-${ie.ie_type}-${ie.instance}-${idx}`}  // ✅ 고유 key
                // style={{ fontSize: "14px", backgroundColor:bgColor[level]||"#010101" }}
                >
            <tbody>

          <tr style={{ fontSize: "14px", backgroundColor:bgColor[level]||"#010101" }} >
            <th style={{ fontSize: "14px", backgroundColor:bgColor[level]||"#010101" }} >
              Type
            </th>
            <td style={{ fontSize: "14px", backgroundColor:bgColor[level]||"#010101" }} >
              {ie.type_str} [{ie.ie_type}]
            </td>
          </tr>
          <tr >
            <th> Len </th>
            <td> {ie.length} <i>bytes</i></td>
          </tr>
          <tr >
            <th> Instance </th>
            <td> {ie.instance} </td>
          </tr>
              {!isGrouped && (
          <tr >
            <th> Value </th>
            <td> 
                {/* {ie.sub_ies.length === 0 ? (
                  ie.ie_type === 1 || ie.ie_type === 75 || ie.ie_type === 76 ? (
                    decodeBCD(ie.value)
                  ) : ie.ie_type === 71 ? (
                      <pre>{ decodeAPN(ie.value) }</pre>
                  ) : ie.ie_type === 72 ? (
                    <pre>{decodeAMBR(ie.value)}</pre>
                  ) : ie.ie_type === 73 ? (
                    <pre>{decodeEBI(ie.value)}</pre>
                  ) : ie.ie_type === 80 ? (
                    <pre> {decodeBearerQoS(ie.value, 0)} </pre>
                  ) : ie.ie_type === 87 ? (
                    <pre>{formatFTEID(decodeFTEID(ie.value))}</pre>
                  ) : (
                    ie.value.length > 0
                      ? "0x" + ie.value.map((b) => b.toString(16).padStart(2, "0")).join(" ")
                      : "(empty)"
                  )
                ) : null} */}
                    {renderIeValue(ie.ie_value)}
            </td>
          </tr>
          )}


          {/* {ie.sub_ies.length > 0 && ( */}
          {isGrouped && (
            <tr >
              <td className="ie-group" colSpan="2"
                  style={{ paddingLeft: "10px", paddingRight: "10px", background:"#a4b1fa" }}>
                <b>Grouped IE Contents</b>
                <GtpIeSimpleTable ies={subIes} level={level + 1}
                                      onHoverRaw={onHoverRaw}

                />
              </td>
            </tr>
          )}

        </tbody>
      </table>
        </div>
      );

    })}
    </>
  )
}

function GtpIeTable({ ies, level = 0 })
{
  const bgColor=[ "#0ff0f0", "#04f010ff", "#00e0e0" ];

  return (
    <>
    {ies.map((ie, idx) => {
      const subIes = ie.ie_value?.SubIeList;
      const isGrouped = Array.isArray(subIes) && subIes.length > 0;

      return (
      <table className="table table-bordered table-sm"
            style={{ fontSize: "14px" }}>
        <tbody>
          <tr>
            <th colSpan="33"
                style= {{ background: bgColor[level]??"#fa2345" }} >
                  {ie.type_str}
            </th>
          </tr>

          <tr>
             <th style={{textAlign:"center"}}>Bit</th>
             {[...Array(32)].map((_, i) => (
                <th  style={{textAlign:"center"}}key={i}>{i}</th>
             ))}
          </tr>

          <tr key={idx} style={{ background: "#f0f0f0" }} >
            <th style={{textAlign:"center"}}>0</th> {/* //<---- */}

            <td colSpan="8" style={{
              textAlign:"center"}} >
                Type: {ie.type_str} [{ie.ie_type}]
            </td>
                
            <td colSpan="16" style={{ textAlign: "center" }}> Length: {ie.length} </td>
            <td colSpan="4"style={{ textAlign: "center" }}> Spare </td>
            <td colSpan="4" style={{ textAlign: "center" }}> Instance: {ie.instance} </td>
          </tr>

          {!isGrouped && (
            <tr>
              <th>32</th>
              <td colSpan="32">
                  {/* {ie.raw && ie.raw.length > 0 ? */}
                    {/* "0x"+ie.raw.map((b) =>b.toString(16).padStart(2,"0")).join(""):"(empth)" } */}
                    {renderIeValue(ie.ie_value)}

                </td>
            </tr>
          )}

          {isGrouped && (
            <tr>
              <td colSpan="33" style={{ paddingLeft: "20px" }}>
                <b>Grouped IE Contents:</b>
                {/* <GtpIeTable ies={ie.ie_value.SubIeList} level={level + 1} /> */}
                 <GtpIeTable ies={subIes} level={level + 1} />
              </td>
            </tr>
          )}

        </tbody>
      </table>
        );
    })}
    </>
  );
}

// function GtpIeTable({ ies, level = 0 }) {
//   return (
//       <table className="table table-bordered table-sm" style={{ fontSize: "14px" }}>
//         <tbody>
//             <tr>
//               <th style={{ textAlign:"center", borderLeft: "" }}>Octet</th>
//               <th colSpan="8">0</th>
//               <th colSpan="8">1</th>
//               <th colSpan="8">2</th>
//               <th colSpan="8">3</th>
//             </tr>
//           <tr>
//             <th style={{textAlign:"center"}}>Bit</th>
//             {[...Array(32)].map((_, i) => (
//                 <th  style={{textAlign:"center"}}key={i}>{i}</th>
//             ))}
//           </tr>

//         {ies.map((ie, idx) => (
//           <React.Fragment key={idx}>
//             <tr>
//               <th></th>
//               <th colSpan="32" style={{background:"#f0f0f0"}} >{ie.type_str}</th>
//             </tr>

//           <tr key={idx}
//             style={{ background: "#f0f0f0" }}
//           >
//             <th style={{textAlign:"center"}}>{0+(32*idx)}</th>

//             <td colSpan="8" style={{
//               textAlign:"center"}} >
//               <b>
//                 {ie.ie_type}
//               </b>
//             </td>
                
//             <td colSpan="16" style={{ textAlign: "center" }}> Length: {ie.length} </td>
//             <td colSpan="4"style={{ textAlign: "center" }}> Spare </td>
//             <td colSpan="4" style={{ textAlign: "center" }}> Instance: {ie.instance} </td>
//           </tr>

//             {ie.sub_ies.length === 0 && (
//               <tr>
//                 <th></th>
//                 <td colSpan="32">

//                   {
//                     ie.ie_type === 1 || ie.ie_type===75 || ie.ie_type===76 ? (
//                       decodeBCD(ie.value)+"  "
//                     ): ie.ie_type===71 ? (
//                       decodeAPN(ie.value)+" "
//                     ): (
//                       "0x"+(ie.value.length > 0
//                         ? ie.value.map((b) => b.toString(16).padStart(2, "0")).join("")
//                         : "(empty)"))
//                     }
                  
//                 </td>
//               </tr>
//             )}

//             {ie.sub_ies.length > 0 && (
//               <tr>
//                 <td colSpan="33" style={{ paddingLeft: "20px" }}>
//                   <b>Grouped IE Contents:</b>
//                   <GtpIeTable ies={ie.sub_ies} level={level + 1} />
//                 </td>
//               </tr>
//             )}
//         </React.Fragment>
//         ))}
//       </tbody>
//     </table>
//   );
// }



export default function GtpHeader({ gtp }) {
  const [viewMode, setViewMode] = useState("decoded");
    const [hoveredRaw, setHoveredRaw] = useState(null); // ★ hover 상태
    const [hoverTop, setHoverTop] = useState(0);  // 두 번째 HexDump top


const fullHexRef = useRef();

useEffect(() => {

  console.log("useEffect 실행");
  console.log("fullHexRef.current:", fullHexRef.current);

  if (fullHexRef.current) {
    console.log("offsetHeight:", fullHexRef.current.offsetHeight);

    setHoverTop(fullHexRef.current.offsetHeight + 12); // 12px gap
  }
}, [viewMode, gtp.raw]); // 메시지가 바뀌면 갱신
// useEffect(() => {
//   if (!fullHexRef.current) return;

//   const observer = new ResizeObserver(() => {
//     console.log("ResizeObserver fired, height:", fullHexRef.current.offsetHeight);
//     setHoverTop(fullHexRef.current.offsetHeight + 12);
//   });

//   observer.observe(fullHexRef.current);

//   return () => observer.disconnect();
// }, [gtp.raw]);


  if (!gtp) return null;

  return (
    <div className="card mb-3">
      <div className="card-header gtp-header d-flex justify-content-between align-items-center">
        <strong>Application Layer</strong>
          <div className="form-check form-switch d-inline-flex align-items-center ms-3" style={{ fontSize: "14px" }} >


            {/* Label 먼저 */}
            <label className="form-check-label me-5" htmlFor="gtpSwitch">
              {viewMode === "raw" ? "Raw" : "Decoded"}
            </label>


            {/* Switch 버튼 */}
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
                      {/* <GtpIeSimpleViewer ies={gtp.ies} /> */}
                      <IeViewer ies={gtp.ies} onHoverRaw={setHoveredRaw} />  {/* 여기서 호출 */}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* <div 
               style={{
                  position: "sticky",
                  top: "10px",
                  height: "fit-content",   // 높이 지정
                  overflowX: "auto",
                  background: "#111a23",
                  zIndex: 1000,
                  borderRadius: "10px"
              }}
            >
              <GtpHexDump raw={gtp.raw} /> 
            {hoveredRaw ? <GtpHexDump raw={hoveredRaw} /> : <div>Hover an IE to see raw data</div>}
            </div>
          </div> */}
          {/* 오른쪽: HexDump 영역 */}
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
      }}
    >
      <GtpHexDump raw={gtp.raw} />
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
      {hoveredRaw ? <GtpHexDump raw={hoveredRaw} /> : <div style={{ color: "#888" }}>Hover an IE to see raw data</div>}
    </div>
  </div>
</div>

        ) : (

          <div>
          <table className="ip-table ">
            <tbody>

              <tr>
                <th colSpan="33" style={{ textAlign: "center" }}>
                  <b>GTP Header</b>
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
                <td colSpan="3"><i>Version:</i> {gtp.version}</td>
                <td colSpan="1"><i>P:</i>
                  {gtp.p_flag ? "1" : "0"}
                </td>
                <td colSpan="1"><i>T:</i> {gtp.t_flag ? "1" : "0"}</td>
                <td colSpan="1"><i>MP:</i> {gtp.mp_flag ? "1" : "0"}</td>
                <td colSpan="2"><i>Reserved</i> </td>

                <td colSpan="8"><i>Message Type:</i>{gtp.msg_type_str} [{gtp.msg_type}] </td>
                <td colSpan="16"><i>Message Length:</i>{gtp.msg_len} </td>
              </tr>

              <tr>
                <th>32</th>
                { gtp.t_flag ? (
                  <td colSpan="32"><i>TEID:0x</i>
                      {gtp.teid != null ? gtp.teid.toString(16)
                      // .toUpperCase()
                      .padStart(8, "0") : "-"}
                      {/* {gtp.teid} */}
                  </td>
                ) : (
                  <>
                  <td colSpan="24"><i>Sequence Number:0x</i>
                              {gtp.seq != null ? gtp.seq.toString(16).padStart(8, "0")
                              // .toUpperCase()
                              : "-"}
                  {/* {gtp.seq} */}
                  </td>
                  {/* <td colSpan="8"><i>Sequence Number</i> </td> */}
                  <td colSpan="8"><i>Spare</i> </td>
                  </>
                )}
              </tr>

              <tr>
                <th>64</th>
                { gtp.t_flag ? (
                  <>
                  <td colSpan="24"><i>Sequence Number:0x</i>
                      {gtp.seq != null ? gtp.seq.toString(16)
                        .padStart(6, "0") : "-"}
                  </td>
                  <td colSpan="8"><i>Spare</i> </td>
                  </>
                ):(<></>)}
              </tr>

              <tr>
                <td colSpan="33" style={{ paddingLeft: "20px" }}>
                  <b>IE Contents:</b>
                  <GtpIeViewer ies={gtp.ies} />

                </td>
              </tr>

            </tbody>
          </table>

            <p></p>
          {/* GTP Group IEs */}


          </div>
        )}

      </div>
    </div>
  );

}