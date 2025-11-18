import React, { useState } from "react";

import "./ip.css";

function decodeAPN(bytes) {
  let pos = 0;
  let labels = [];

  while (pos < bytes.length) {
    const len = bytes[pos];
    pos += 1;

    if (len === 0) break; // 종료

    if (pos + len > bytes.length) break; // 잘못된 데이터 보호

    const labelBytes = bytes.slice(pos, pos + len);
    const label = Array.from(labelBytes)
      .map((b) => String.fromCharCode(b))
      .join("");

    labels.push(label);

    pos += len;
  }

  return labels.join(".");
}

// hex string → Uint8Array 로 변환
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
              Type </th>
            <td
            style={{ fontSize: "14px", backgroundColor:bgColor[level]||"#010101" }}
                  // style= {{ background: bgColor[level]??"#fa2345" }}
            > {ie.type_str} [{ie.ie_type}]</td>
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
              {
                ie.ie_type === 1 || ie.ie_type===75 || ie.ie_type===76 ? (
                      decodeBCD(ie.value)
                ):
                 ie.ie_type===71 ? (
                      decodeAPN(ie.value)
                 ): (
                
              "0x"+(ie.value.length > 0 ?

                        ie.value.map((b) => b.toString(16).padStart(2, "0")).join("")
                        : "(empty)")
              )}
              {ie.val}
            </td>
          </tr>


          {ie.sub_ies.length > 0 && (
            <tr >
              <td className="ie-group" colSpan="2"
                  style={{ paddingLeft: "10px", paddingRight: "10px", background:"#a4b1fa" }}>
                <b>Grouped IE Contents:</b>
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

// function GtpIeTable({ ies, level = 0 }) {


//         </tbody>
//       </table>
//     ))}
//     </>
//   )
// }

function GtpIeTable({ ies, level = 0 }) {
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
          {/* <tr>
            <th style={{ textAlign:"center", borderLeft: "" }}>Octet</th>
            <th colSpan="8">0</th>
            <th colSpan="8">1</th>
            <th colSpan="8">2</th>
            <th colSpan="8">3</th>
          </tr> */}
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
                      ie.type_str+": "+
                      decodeAPN(ie.value)
                    ): (
                      ie.type_str+": "+"0x"+(ie.value.length > 0 ?
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
            // style={{ flex: "1 1 auto", overflowX: "auto"
               style={{
                // flex: "1 1 auto",
                // overflowX: "auto",

                // position: "sticky",
                // top: 0,        // 상단으로 고정
                // background: "#111a23", // 배경색 지정 필요 (겹침 방지)
                // zIndex: 10     // 다른 요소 위에 표시

                   position: "sticky",
    top: "10px", // 필요 시 navbar 높이만큼 조정
    // left: 0,
    // right: 0,
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
                              // .toUpperCase()
                              .padStart(6, "0") : "-"}
                  {/* {gtp.seq} */}
                  </td>
                  <td colSpan="8"><i>Spare</i> </td>
                  </>
                ):(<></>)}
              </tr>

<tr>
                <td colSpan="33"
                  style={{ paddingLeft: "20px" }}>
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