import React, { useState } from "react";

import "./ip.css";

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

          {/* <label className="form-check-label ms-2" htmlFor="gtpSwitch">
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
          /> */}
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

                </tbody>
              </table>
            </div>

            <div style={{ flex: "1 1 auto", overflowX: "auto" }}>
              <GtpHexDump raw={gtp.raw} /> 
            </div>
          </div>
        ) : (


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

        </tbody>
      </table>
    )}
      </div>
    </div>
  );

}