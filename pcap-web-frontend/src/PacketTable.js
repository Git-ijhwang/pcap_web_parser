import React, { useState, useRef } from "react";
import {Modal, Button} from "react-bootstrap";
import "./App.css";

import OverlayTrigger from "react-bootstrap/OverlayTrigger";
import Tooltip from "react-bootstrap/Tooltip";
import Layer3Header from "./components/headers/Layer3Header";
import Layer4Header from "./components/headers/Layer4Header";
import GtpHeader from "./components/headers/GtpHeader";


function PacketTable({ packets, fileId, onCallFlow})  {
  const [loadingFlow, setLoadingFlow] = useState(false);
  const [flowError, setFlowError] = useState(null);
  const [callFlow, setCallFlow] = useState(null);

// , currentFile , onFilterChange}) {
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [filterCollapsed, setFilterCollapsed] = useState(false);
  const [modalSections, setModalSections] = useState({
    l3: false,
    l4: false,
    app: false
  });

  // 필터 가능한 프로토콜 목록
  const [filters, setFilters] = useState({
    tcp:   { enabled: false, port: "" },
    udp:   { enabled: false, port: "" },
    ipv4:  { enabled: false, addr: "" },
    ipv6:  { enabled: false, addr: "" },
  });

  const [selected, setSelected] = useState([]);

  const handleClose = () => {
    setShowModal(false);
    setSelectedPacket(null);
  };

  // const fetchCallFlow = async (packetId) => {

  //   setLoadingFlow(true);
  //   setFlowError(null);

  //   try {
  //     console.log("PacketID:", packetId);
  //     const res = await fetch("/api/gtp/callflow", {
  //       method: "POST",
  //       headers: {
  //         "Content-Type": "application/json",
  //       },
  //       body: JSON.stringify(
  //         {file_id: fileId , packet_id: packetId}),
  //     });

  //     if (!res.ok) {
  //       throw new Error(`HTTP ${res.status}`);
  //     }

  //           const data = await res.json();
  //           setCallFlow(data);
  //           setShowCallFlow(true);
  //       }
  //       catch (err) {
  //           // console.err("Callflow fetch failed:", err);
  //           setFlowError("Failed to load call flow");
  //       } finally {
  //           setLoadingFlow(false);
  //       }
  //   };

  const fetchPacketDetail = async (id) => {
    if (!fileId) {
      alert("No file selected!");
      return;
    }

    try {
      const res = await fetch(
        `/api/packet_detail?file_id=${fileId}&id=${encodeURIComponent(id)}`
        // `/api/packet_detail?file=${encodeURIComponent(currentFile)}&id=${encodeURIComponent(id)}`
      );

      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`Server ${res.status}: ${txt}`);
      }

      const data = await res.json();
      setSelectedPacket(data);
      setShowModal(true);
    }
    catch (err) {
      console.error(err);
      alert("Failed to fetch packet detail");
    }
  };


  // packets가 없으면 Modal 렌더링 자체를 하지 않음
  function isValidPort(port) {
    const n = Number(port);
    if ( Number.isInteger(n) && n > 0 && n < 65535 ) {
      return true;
    }
    return false;
  }

  function isValidIPv4(ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  }

  function isValidIPv6(ip) {
    return ip.includes(":");
  }

  const filteredPackets = packets?.filter(pkt => {

    if (filters.tcp.enabled) {
      if (pkt.protocol !== "TCP") return false;
      if (filters.tcp.port && isValidPort(filters.tcp.port)) {
        const n = Number(filters.tcp.port);
        if (pkt.src_port !== n && pkt.dst_port !== n) return false;
      }
    }

    if (filters.udp.enabled) {
      if (pkt.protocol !== "UDP") return false;
      if (filters.udp.port && isValidPort(filters.udp.port)) {
        const n = Number(filters.udp.port);
        if (pkt.src_port !== n && pkt.dst_port !== n) return false;
      }
    }
    if (filters.ipv4.enabled) {
      if (isValidIPv4(filters.ipv4.addr)) {
        if ( pkt.src_ip !== filters.ipv4.addr &&
          pkt.dst_ip !== filters.ipv4.addr)
          return false;
      }
    }
    if (filters.ipv6.enabled) {
      if (isValidIPv6(filters.ipv6.addr)) {
        if ( pkt.src_ip !== filters.ipv6.addr &&
          pkt.dst_ip !== filters.ipv6.addr)
          return false;
      }
    }

    return true;

  });

  return (
    <div className="container mt-4">

{!onCallFlow && (
      <button type="button"
          className= "btn btn-sm btn-outline-secondary position-absolute collaps-btn"
          onClick={() => setFilterCollapsed(c => !c)}
          aria-label="toggle collapse"
          >
        <i className={`bi ${filterCollapsed ? "bi-chevron-down" : "bi-chevron-up"}`} />
      </button>
)}

      <div className={`d-flex card gap-2 p-2 filter-wrapper `} >

        <h5>Packet Filters</h5>
        <div className={`d-flex gap-2 pkt-filter-box
        ${filterCollapsed ? "filterCollapsed" : ""}
        `}>

          {/* Layer-3 */}
          <div className="l3-filter  card  gap-2 flex-fill" >
            {/* IPv4 */}
            <div className="d-flex align-items-center gap-2">
              <input
                type="checkbox"
                checked={filters.ipv4.enabled}
                onChange={e =>
                  setFilters(f => ({
                    ...f,
                    ipv4: { ...f.ipv4, enabled: e.target.checked }
                  }))
                }
              />
              <span>IPv4</span>
              <input
                type="text"
                className="form-control form-control-sm"
                style={{ width: "200px" }}
                placeholder="10.0.0.1"
                disabled={!filters.ipv4.enabled}
                value={filters.ipv4.addr}
                onChange={e =>
                  setFilters(f => ({
                    ...f,
                    ipv4: { ...f.ipv4, addr: e.target.value }
                  }))
                }
              />
            </div>

            {/* IPv6 */}
            <div className="d-flex align-items-center gap-2">
              <input
                type="checkbox"
                checked={filters.ipv6.enabled}
                onChange={e =>
                  setFilters(f => ({
                    ...f,
                    ipv6: { ...f.ipv6, enabled: e.target.checked }
                  }))
                }
              />
              <span>IPv6</span>
              <input
                type="text"
                className="form-control form-control-sm"
                style={{ width: "260px" }}
                placeholder="2001:db8::1"
                disabled={!filters.ipv6.enabled}
                value={filters.ipv6.addr}
                onChange={e =>
                  setFilters(f => ({
                    ...f,
                    ipv6: { ...f.ipv6, addr: e.target.value }
                  }))
                }
              />
            </div>
          </div>

          {/* Layer-4 */}
          <div className="l4-filter  card  gap-2 flex-fill" >
            {/* TCP */}
            <div className="d-flex align-items-center gap-2">
              <input
                type="checkbox"
                checked={filters.tcp.enabled}
                onChange={e =>
                  setFilters(f => ({
                    ...f,
                    tcp: { ...f.tcp, enabled: e.target.checked }
                  }))
                }
              />
              <span>TCP</span>
              <input
                type="text"
                className="form-control form-control-sm"
                style={{ width: "120px" }}
                placeholder="port"
                disabled={!filters.tcp.enabled}
                value={filters.tcp.port}
                onChange={e =>
                  setFilters(f => ({
                    ...f,
                    tcp: { ...f.tcp, port: e.target.value }
                  }))
                }
              />
            </div>

            {/* UDP */}
            <div className="d-flex align-items-center gap-2">
              <input
                type="checkbox"
                checked={filters.udp.enabled}
                onChange={e =>
                  setFilters(f => ({
                    ...f,
                    udp: { ...f.udp, enabled: e.target.checked }
                  }))
                }
              />
              <span>UDP</span>
              <input
                type="text"
                className="form-control form-control-sm"
                style={{ width: "120px" }}
                placeholder="port"
                disabled={!filters.udp.enabled}
                value={filters.udp.port}
                onChange={e =>
                  setFilters(f => ({
                    ...f,
                    udp: { ...f.udp, port: e.target.value }
                  }))
                }
              />
            </div>
          </div>
        </div>

      </div>

      <table className="table table-striped table-hover table-bordered mt-3">
        <thead className="table-dark">
          <tr>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Src Port</th>
            <th>Dst Port</th>
            <th>Protocol</th>
            <th>Description</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {filteredPackets || filteredPackets.length > 0 ? (
            filteredPackets.map((pkt) => (

            <tr key={pkt.id}
              onClick={() => fetchPacketDetail(pkt.id) }
              style={{ cursor: "pointer" }}>

              <td>{pkt.id}</td>
              <td>{pkt.ts}</td>
              <td>{pkt.src_ip}</td>
              <td>{pkt.dst_ip}</td>
              <td>{pkt.src_port}</td>
              <td>{pkt.dst_port}</td>
              <td>{pkt.protocol}</td>
              <td>{pkt.description}</td>
              <td>
                {pkt.description === "Create Session Request [32]" && onCallFlow && (
                  <button
                    className="btn btn-sm btn-outline-primary"
                    onClick={(e) => {
                      e.stopPropagation();
                      onCallFlow(pkt.id);
                    }} >
                    <i className="bi bi-diagram-3"></i>
                  </button>
                )
                }
              </td>
            </tr>
          ))
        ):(
          <tr>
            <td colSpan="8" className="text-center text-muted">
              No packets loaded
            </td>
            </tr>
        )}
        </tbody>
      </table>




      {/* ✅ Modal은 packets가 존재하고 선택된 패킷이 있을 때만 보여줌 */}
        {selectedPacket && (
        <Modal show={showModal} onHide={handleClose} centered
          dialogClassName="my-wide-modal"
        >
          <Modal.Header closeButton>
            <Modal.Title>Packet Details</Modal.Title>
          </Modal.Header>

          <Modal.Body>
            {selectedPacket && (
              <div style={{ fontFamily: "monospace", fontSize: "14px" }}>

                {/* Packet ID */}
                <div className="mb-3">
                  <h5 style={{ borderBottom: "1px solid #ccc", paddingBottom: "4px" }}>
                    Packet #{selectedPacket.id}
                  </h5>
                </div>

                {/* IP Section */}
                {selectedPacket.packet.l3.map((l3, idx) => (
                  <Layer3Header key={idx} l3={l3} idx={idx} />
                )) }

                {/* L4 Section */}
                <Layer4Header l4={selectedPacket.packet.l4}/>

                {/* Application Layer (GTP) */}
                {selectedPacket?.packet?.app?.GTP && (
                  <GtpHeader gtp={selectedPacket.packet.app.GTP} />
                )}

              </div>
            )}
          </Modal.Body>

          <Modal.Footer>
            <Button variant="secondary" onClick={handleClose}>
              Close
            </Button>
          </Modal.Footer>

        </Modal>
      )}
    </div>
  );
}

export default PacketTable;