/* global BigInt */

import React, { useState, useRef, useEffect } from "react";
import BitGridHeader from '../common/BitGridHeader';
import HexDump from '../common/HexDump';
import PfcpIeViewer from './PfcpIeViewer';
import PfcpIeTable from './PfcpIeTable';
import "./PfcpViewer.css";



export default function PfcpHeader({ pfcp }) {
  const [viewMode, setViewMode] = useState("decoded");
  const [hoveredRaw, setHoveredRaw] = useState(null); // ★ hover 상태
  const [hoverTop, setHoverTop] = useState(0);  // 두 번째 HexDump top
  const fullHexRef = useRef();
  const high = Number((BigInt(pfcp.seid) >> 32n) & 0xffffffffn);
  const low  = Number(BigInt(pfcp.seid) & 0xffffffffn);

  useEffect(() => {

    if (fullHexRef.current) {
      setHoverTop(fullHexRef.current.offsetHeight + 12); // 12px gap
    }
  }, [viewMode, pfcp.raw]); // 메시지가 바뀌면 갱신

  if (!pfcp) return null;


  return (
    <div className="card mb-3">
      <div className="card-header pfcp-header d-flex justify-content-between align-items-center">
        <div className="d-flex align-items-center">
          <span className="protocol-badge">L7</span>
        <strong className="protocol-title">PFCP</strong>
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

      <div className="card-body pfcp-card-body">
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
                    <td>{pfcp.version}</td>
                  </tr>
                  
                  <tr>
                    <th>FO Flag</th>
                    <td>{ pfcp.fo_flag?  "1":"0" }</td>
                  </tr>
                  
                  <tr>
                    <th>MP Flag</th>
                    <td>{ pfcp.mp_flag?  "1":"0" }</td>
                  </tr>
                  
                  <tr>
                    <th>S Flag</th>
                    <td>{ pfcp.s_flag?  "1":"0" }</td>
                  </tr>
                  
                  <tr>
                    <th>Message Type</th>
                    <td>{pfcp.msg_type_str} [{pfcp.msg_type}]</td>
                  </tr>
                  
                  <tr>
                    <th>Message Length</th>
                    <td>{pfcp.msg_len}</td>
                  </tr>
                  
                  { pfcp.s_flag ? (
                    <tr>
                      <th>SEID</th>
                      <td>
                        0x{ pfcp.seid }
                      </td>
                    </tr>
                  ) : (
                    <></>
                  )}

                  <tr>
                    <th>Sequence</th>
                    <td>
                      0x{ pfcp.seq }
                    </td>
                  </tr>

                  <tr >
                    <td colSpan="2" style={{backgroundColor:"#a3b2c3"}}>
                      PFCP IEs
                      <PfcpIeViewer ies={pfcp.ies} onHoverRaw={setHoveredRaw} />  {/* 여기서 호출 */}
                    </td>
                  </tr>

                </tbody>
              </table>

            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "12px", flex: "0 0 400px" }}>

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
                <HexDump raw={pfcp.raw} />
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

        ):(
          <div>
            {/* <table className="pfcp-table "> */}
            <table className="bit-grid-table ">

              <BitGridHeader showOctet={true}/>

              <tbody>
                <tr>
                { pfcp.s_flag ? (
                  <th rowSpan="4" colSpan="2" className="vertical pfcp-header">
                    PFCP Header
                  </th>
                ):(
                  <th rowSpan="2" colSpan="2" className="vertical pfcp-header">
                    PFCP Header
                  </th>
                )}
                  <td colSpan="3" className="field"><i>Version:</i> {pfcp.version}</td>
                  <td colSpan="2" className="field"><i>Spare</i> </td>
                  <td colSpan="1" className="field"><i>FO:</i> {pfcp.fo_flag ? "1" : "0"}</td>
                  <td colSpan="1" className="field"><i>MP:</i> {pfcp.mp_flag ? "1" : "0"}</td>
                  <td colSpan="1" className="field"><i>S:</i> {pfcp.s_flag ? "1" : "0"}</td>

                  <td colSpan="8" className="field"><i>Message Type: </i> {pfcp.msg_type_str}[{pfcp.msg_type}] </td>
                  <td colSpan="16" className="field"><i>Length: </i>{pfcp.msg_len} </td>
                </tr>

                { pfcp.s_flag ? (
                  <>
                  <tr>
                    <td colSpan="32" className="field">
                      <i>SEID[63:32]</i> : 0x{high.toString(16).padStart(8,'0')}
                    </td>
                  </tr>

                  <tr>
                    <td colSpan="32" className="field">
                      <i>SEID[31:0]</i> : 0x{low.toString(16).padStart(8,'0')}
                    </td>
                  </tr>
                  </>
                ):( <></>)}

                <tr>
                    <>
                      <td colSpan="24" className="field"><i>Sequence Number:0x</i>
                        {pfcp.seq != null ? pfcp.seq.toString(16).padStart(8, "0")
                        // .toUpperCase()
                        : "-"}
                        {/* {pfcp.seq} */}
                      </td>
                      {/* <td colSpan="8"><i>Sequence Number</i> </td> */}
                      <td colSpan="8" className="field"><i>Spare</i> </td>
                    </>
                </tr>
                <PfcpIeTable ies={pfcp.ies} />
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}