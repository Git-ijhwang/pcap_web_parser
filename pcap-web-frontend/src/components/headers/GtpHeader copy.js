import React, { useState } from "react";

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
  return (
    <div>
      <GtpIeSimpleTable ies={ies} />
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

function GtpIeSimpleTable({ ies, level = 0 }) {
  const bgColor=[ "#0ff0f0", "#04f010ff", "#00e0e0" ];
  return (
    <>
    {ies.map((ie, idx) => (
      <table className="table table-bordered table-sm ie-table"
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
          <tr >
            <th> Value </th>
            <td> 
                {ie.sub_ies.length === 0 ? (
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
                ) : null}
            </td>
          </tr>


          {ie.sub_ies.length > 0 && (
            <tr >
              <td className="ie-group" colSpan="2"
                  style={{ paddingLeft: "10px", paddingRight: "10px", background:"#a4b1fa" }}>
                <b>Grouped IE Contents</b>
                <GtpIeSimpleTable ies={ie.sub_ies} level={level + 1} />
              </td>
            </tr>
          )}

        </tbody>
      </table>

    ))}
    </>
  )
}

function GtpIeTable({ ies, level = 0 })
{
  const bgColor=[ "#0ff0f0", "#04f010ff", "#00e0e0" ];
  return (
    <>
    {ies.map((ie, idx) => (
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
            <th style={{textAlign:"center"}}>0</th>

            <td colSpan="8" style={{
              textAlign:"center"}} >
                Type: {ie.ie_type}
            </td>
                
            <td colSpan="16" style={{ textAlign: "center" }}> Length: {ie.length} </td>
            <td colSpan="4"style={{ textAlign: "center" }}> Spare </td>
            <td colSpan="4" style={{ textAlign: "center" }}> Instance: {ie.instance} </td>
          </tr>

          {ie.sub_ies.length === 0 && (
            <tr>
              <th></th>
                <td colSpan="32">
                  {
                    ie.ie_type === 1 || ie.ie_type===75 || ie.ie_type===76 ? (
                      ie.type_str+": "+decodeBCD(ie.value)
                    ): ie.ie_type===71 ? (
                      ie.type_str+": "+decodeAPN(ie.value)
                    ): ie.ie_type === 80 ? (
                        decodeBearerQoS(ie.value, 1)
                    ):(
                      ie.type_str+": "+
                      (ie.value.length > 0 ?
                      "0x"+
                        ie.value.map((b) => b.toString(16).padStart(2, "0")).join("")
                        : "(empty)")
                    )
                  }
                  
                </td>
            </tr>
          )}

          {ie.sub_ies.length > 0 && (
            <tr>
              <td colSpan="33"
              style={{ paddingLeft: "20px" }}>
                <b>Grouped IE Contents:</b>
                <GtpIeTable ies={ie.sub_ies} level={level + 1} />
              </td>
            </tr>
          )}

        </tbody>
      </table>

    ))}
    </>
  )
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
                      <GtpIeSimpleViewer ies={gtp.ies} />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div 
               style={{
                  position: "sticky",
                  top: "10px",
                  height: "400px",   // 높이 지정
                  overflowX: "auto",
                  background: "#111a23",
                  zIndex: 1000,
                  borderRadius: "10px"
              }}
            >
              <GtpHexDump raw={gtp.raw} /> 
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