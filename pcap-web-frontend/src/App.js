// src/App.js
import React, { useState, useRef } from "react";
// import PacketTable from "./-PacketTable";
import {Modal, Button} from "react-bootstrap";
// import "./ip.css";
import "./App.css";

import OverlayTrigger from "react-bootstrap/OverlayTrigger";
import Tooltip from "react-bootstrap/Tooltip";
import IpHeader from "./components/headers/IpHeader";
import Layer4Header from "./components/headers/Layer4Header";
import GtpHeader from "./components/headers/GtpHeader";
import Layer3Header from "./components/headers/Layer3Header";


function PacketTable({ packets, currentFile , onFilterChange}) {

  const [selectedPacket, setSelectedPacket] = useState(null);
  const [showModal, setShowModal] = useState(false);
  // const [collapsed, setCollapsed] = useState(null);

  const [filterCollapsed, setFilterCollapsed] = useState(false);

  const [modalSections, setModalSections] = useState({
    l3: false,
    l4: false,
    app: false
  });
  // 필터 가능한 프로토콜 목록
  const protocols = [
    { name: "TCP", value: "tcp" },
    { name: "UDP", value: "udp" },
    { name: "ICMP", value: "icmp" },
    { name: "GTP", value: "gtp" },
    { name: "IPv4", value: "ipv4" },
    { name: "IPv6", value: "ipv6" },
  ];

  const [filters, setFilters] = useState({
    tcp:   { enabled: false, port: "" },
    udp:   { enabled: false, port: "" },
    ipv4:  { enabled: false, addr: "" },
    ipv6:  { enabled: false, addr: "" },
  });

  const protocolMeta = {
    ipv4: { layer:3, name: "IPv4"},
    ipv6: { layer:3, name: "IPv6"},
    tcp:  { layer:4, name: "TCP"},
    udp:  { layer:4, name: "UDP"},
    icmp: { layer:4, name: "ICMP"},
    gtp:  { layer:7, name: "GTP"},
  };

  const [selected, setSelected] = useState([]);

  const toggleProtocol = (value) => {
    const newSelected = selected.includes(value)
      ? selected.filter(v=>v !== value)
      : [...selected, value];
    
      setSelected(newSelected);
      if (onFilterChange) onFilterChange(newSelected);
  };
  const HoverField = ({ children, tooltip }) => (
    <OverlayTrigger
      placement="top"
      overlay={<Tooltip>{tooltip}</Tooltip>}
    >
      <td style={{ cursor: "help" }}>
        {children}
      </td>
    </OverlayTrigger>
  );

  const handleShow = (pkt) => {
    setSelectedPacket(pkt);
    setShowModal(true);
  };

  const handleClose = () => {
    setShowModal(false);
    setSelectedPacket(null);
  };

  const fetchPacketDetail = async (id) => {
    if (!currentFile) {
      alert("No file selected!");
      return;
    }

    try {
      const res = await fetch(
        `/api/packet_detail?file=${encodeURIComponent(currentFile)}&id=${encodeURIComponent(id)}`
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


  const toggleModalSection = (section) => {
    setModalSections(prev => ({ ...prev, [section]: !prev[section] }));
  };


  // packets가 없으면 Modal 렌더링 자체를 하지 않음
  // const shouldShowModal = showModal && selectedPacket !== null;
  function isValidPort(port)
  {
    const n = Number(port);
    if ( Number.isInteger(n) && n > 0 && n <65535 ) {
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

      <button type="button"
          className= "btn btn-sm btn-outline-secondary position-absolute"
          style={{top:"12px", right:"12px", margin:"12px"}}
          onClick={() => setFilterCollapsed(c => !c)}
          aria-label="toggle collapse"
          >
        <i className={`bi ${filterCollapsed ? "bi-chevron-down" : "bi-chevron-up"}`} />
      </button>

      <div className={`d-flex card gap-2 p-2 filter-wrapper ${filterCollapsed ? "filterCollapsed" : ""}`} >

      <h5>Packet Filters</h5>
      <div className="d-flex gap-2">

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

function ResultBlock({ result }) {
  if (!result) return null;
  if (result.error) {
    return (
      <div className="alert alert-danger mt-3">
        <strong> Error: </strong> {result.error}
      </div>
    );
  }
  const packets = result.packets?? [];
  return (
    <div className="mt-4">
      <h3 className="mb-3">
        Parse Result ({result.total_packets} packets)
      </h3>

      <div className="table-responsive">
        <table className="table table-striped table-hover table-bordered align-middle  text-center">
          <thead className="table-dark">
            <tr>
              <th>#</th>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Dest IP</th>
              <th>Src Port</th>
              <th>Dst Port</th>
              <th>Protocol</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            { packets.map(pkt => (
                <tr key={pkt.id}>
                  <td>{pkt.id}</td>
                  <td>{pkt.ts}</td>

                  <td>{pkt.src_ip}</td>
                  <td>{pkt.dst_ip}</td>

                  <td>{pkt.src_port}</td>
                  <td>{pkt.dst_port}</td>
                 
                  <td>{pkt.protocol}</td>
                  <td>{pkt.description}</td>
                </tr>
            ))
          }
          </tbody>
        </table>
      </div>
    </div>
  );
}

function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [currentFile, setCurrentFile] = useState(null);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [collapsed, setCollapsed] = useState(null);


  // 파일 input ref 생성
  const fileInputRef = useRef(null);

  const onFileChange = (e) => {
    setFile(e.target.files?.[0] ?? null);
    setResult(null);
  };

  const resetAll = async () => {
    setFile(null);
    setResult(null);

    // input 파일 초기화
    if (fileInputRef.current) {
      fileInputRef.current.value = null;
    }

    try {
      await fetch("/api/cleanup", {
        method: "POST"
      });
    } catch (err) {
      console.error("Cleanup failed:", err);
    }
  };

  const upload = async () => {
    if (!file) {
      alert("Please choose a file first");
      return;
    }
    setLoading(true);
    setResult(null);

    try {
      const form = new FormData();
      form.append("pcap", file);

      const res = await fetch("/api/parse", {
        method: "POST",
        body: form
      });

      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`Server ${res.status}: ${txt}`);
      }

      const json = await res.json();
      setResult(json);

      setCurrentFile(json.file)

    } catch (err) {
      console.error(err);
      setResult({ error: String(err) });

    } finally {
      setLoading(false);
    }
  };


  return (
    <div className="container mt-4">
      <div className="fileopen-card card shadow p-4 ">

        <button type="button"
            className= "btn btn-sm btn-outline-secondary position-absolute"
            style={{top:"12px", right:"12px", margin:"12px"}}
            onClick={() => setCollapsed(c => !c)}
            aria-label="toggle collapse"
            >
          <i className={`bi ${collapsed ? "bi-chevron-down" : "bi-chevron-up"}`} />
        </button>

        <h1 className={`mb-3 parser-title
          ${collapsed ? "collapsed" : ""}`}>pcap file Parser </h1>
         {/* 🔽 Collapsible Area */}
        <div className={`collapse-wrapper ${collapsed ? "collapsed" : ""}`} >

          <div className="mb-3">
            {/* <label style={{ display: "block", marginBottom: 8 }}> */}
              <input type="file"
                ref={fileInputRef}       // ref 연결
                className="form-control mb-2" onChange={onFileChange} />
            {/* </label> */}
          </div>

          <div>
            <button
                className="btn btn-primary me-3" 
                onClick={upload}
                disabled={loading || !file} >

              {loading ? "Parsing..." : "Upload & Parse"}
            </button>

            <button
              variant="secondary" 
              className="btn btn-secondary " 
              onClick={ resetAll }
            >
              Reset
            </button>
          </div>

        </div>

      </div>

      <div className="packetlist-card card shadow p-4 ">
        {result?.packets && (
          <PacketTable
              packets={result.packets}
              currentFile={currentFile}
            />
        )}

        <Modal show={selectedPacket !== null} onHide={() => setSelectedPacket(null)} centered size="lg">
          <Modal.Header closeButton>
            <Modal.Title>Packet Detail (ID: {selectedPacket?.id}) </Modal.Title>
          </Modal.Header>
          <Modal.Body>
            {selectedPacket ? (
              <div>
                {Object.entries(selectedPacket).map(([key, value]) => (
                  <p key={key}>
                    <strong>{key}</strong>: {String(value)}
                  </p>
                ))}
              </div>
            ) : null
            }
          </Modal.Body>

          <Modal.Footer>
            <Button variant="secondary"
              onClick={() => setSelectedPacket(null)}>
              Close
            </Button>
          </Modal.Footer>

        </Modal>

          {/* <ResultBlock result={result} /> */}
      </div>
    </div>
  );
}

export default App;
