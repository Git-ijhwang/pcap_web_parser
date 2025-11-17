import React from "react";
import "./ip.css";

export default function GtpHeader({ gtp }) {
  if (!gtp) return null;
  return (
    <div className="card mb-3">
      <div className="card-header gtp-header">
        <strong>Application Layer</strong>
      </div>

      <div className="card-body">

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
              <td colSpan="1"><i>P:</i> {gtp.p_flag ? "1" : "0"}</td>
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

      </div>
    </div>
  );

}