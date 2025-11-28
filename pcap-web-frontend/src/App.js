// src/App.js
import React, { useState } from "react";
// import PacketTable from "./-PacketTable";
import {Modal, Button} from "react-bootstrap";
// import "./ip.css";
import "./App.css";
import OverlayTrigger from "react-bootstrap/OverlayTrigger";
import Tooltip from "react-bootstrap/Tooltip";
import IpHeader from "./components/headers/IpHeader";
import Layer4Header from "./components/headers/Layer4Header";
import GtpHeader from "./components/headers/GtpHeader";

function PacketTable({ packets, currentFile }) {

    const [selectedPacket, setSelectedPacket] = useState(null);
  const [showModal, setShowModal] = useState(false);


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

  // packets가 없으면 Modal 렌더링 자체를 하지 않음
  const shouldShowModal = showModal && selectedPacket !== null;

  return (
        <div className="container mt-4">

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
        {packets && packets.length>0 ? (
          packets.map((pkt) => (
          <tr key={pkt.id}
              onClick={() =>
                // onSelect(pkt)
                fetchPacketDetail(pkt.id)
              }
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
      {shouldShowModal && (
        <Modal show={shouldShowModal} onHide={handleClose} centered
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
                <IpHeader ip={selectedPacket.packet.ip}/>

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


  const onFileChange = (e) => {
    setFile(e.target.files?.[0] ?? null);
    setResult(null);
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

      // console.log("print out json: ======>", json);
      setCurrentFile(json.file)
      // console.log("print out currentFile:", currentFile);

    } catch (err) {
      console.error(err);
      setResult({ error: String(err) });

    } finally {
      setLoading(false);
    }
  };


  return (
    // <div style={{ maxWidth: 1100, margin: "24px auto", padding: 12, fontFamily: "Inter, Arial, sans-serif" }}>
    <div className="container my-4">
      <div className="card shadow p-4">
        <h1 className="mb-3">pcap file Parser </h1>

      <div className="mb-3">
        {/* <label style={{ display: "block", marginBottom: 8 }}> */}
          <input type="file" className="form-control mb-2" onChange={onFileChange} />
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
              onClick={() => { setFile(null); setResult(null); }} >
            Reset
          </button>
        </div>

      {result?.packets && (
          <PacketTable
              packets={result.packets}
              // onSelect={setSelectedPacket}
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
          <Button variant="secondary" onClick={() => setSelectedPacket(null)}>
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
