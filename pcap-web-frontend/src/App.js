// src/App.js
import React, { useState } from "react";
// import PacketTable from "./-PacketTable";
import {Modal, Button} from "react-bootstrap";


function PacketTable({ packets, currentFile }) {
  // console.log(packets.length);
  // if (!packets || packets.length === 0)
  //   return <p>No packets parsed yet.</p>;

    const [selectedPacket, setSelectedPacket] = useState(null);
  const [showModal, setShowModal] = useState(false);
  // const [currentFile, setCurrentFile] = useState(null);


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
      console.log("Current file name is: ", currentFile);
      console.log("Current id  is: ", id);

      const res = await fetch(
                    `/api/packet_detail?file=${encodeURIComponent(currentFile)}&id=${encodeURIComponent(id)}`
      );

      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`Server ${res.status}: ${txt}`);
      }
      console.log(res)

      const data = await res.json();
      console.log(data)
      setSelectedPacket(data);
      setShowModal(true);
      // return res.json();
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
        <Modal show={shouldShowModal} onHide={handleClose} centered>
          <Modal.Header closeButton>
            <Modal.Title>Packet Details</Modal.Title>
          </Modal.Header>
          <Modal.Body>
            {/*
            {selectedPacket && (
              <>
                <p><strong>ID:</strong> {selectedPacket.id}</p>
                <p><strong>Source IP:</strong> {selectedPacket.packet.ip.src_addr}</p>
                <p><strong>Destination IP:</strong> {selectedPacket.packet.ip.dst_addr}</p>
                <p><strong>L4 Src port:</strong> {selectedPacket.packet.l4.UDP.src_port}</p>
                <p><strong>L4 Dst port:</strong> {selectedPacket.packet.l4.UDP.dst_port}</p>
                <p><strong>GTP:</strong> {selectedPacket.packet.l4.UDP.dst_port}</p>
              </>
            )}
            */}
  {selectedPacket && (
    <div style={{ fontFamily: "monospace", fontSize: "14px" }}>

      {/* Packet ID */}
      <div className="mb-3">
        <h5 style={{ borderBottom: "1px solid #ccc", paddingBottom: "4px" }}>
          Packet #{selectedPacket.id}
        </h5>
      </div>

      {/* IP Section */}
      <div className="card mb-3">
        <div className="card-header">
          <strong>IP Layer</strong>
        </div>
        <div className="card-body">
          <div style={{ marginLeft: "12px" }}>
            <p><strong>Source:</strong> {selectedPacket.packet.ip.src_addr}</p>
            <p><strong>Destination:</strong> {selectedPacket.packet.ip.dst_addr}</p>
          </div>
        </div>
      </div>

      {/* L4 Section */}
      <div className="card mb-3">
        <div className="card-header">
          <strong>Layer 4 (Transport)</strong>
        </div>
        <div className="card-body">

          {"UDP" in selectedPacket.packet.l4 && (
            <div style={{ marginLeft: "12px" }}>
              <p><strong>Protocol:</strong> UDP</p>
              <p><strong>Src Port:</strong> {selectedPacket.packet.l4.UDP.src_port}</p>
              <p><strong>Dst Port:</strong> {selectedPacket.packet.l4.UDP.dst_port}</p>
            </div>
          )}

          {"TCP" in selectedPacket.packet.l4 && (
            <div style={{ marginLeft: "12px" }}>
              <p><strong>Protocol:</strong> TCP</p>
              <p><strong>Seq:</strong> {selectedPacket.packet.l4.TCP.seq}</p>
              <p><strong>Src Port:</strong> {selectedPacket.packet.l4.TCP.src_port}</p>
              <p><strong>Dst Port:</strong> {selectedPacket.packet.l4.TCP.dst_port}</p>
            </div>
          )}

        </div>
      </div>

      {/* Application Layer (GTP) */}
      <div className="card">
        <div className="card-header">
          <strong>Application Layer (GTP)</strong>
        </div>
        <div className="card-body">

          {"GTP" in selectedPacket.packet.app && (
            <div style={{ marginLeft: "12px" }}>
              <p><strong>Message Type:</strong> {selectedPacket.packet.app.GTP.msg_type}</p>
              <p><strong>Description:</strong> {selectedPacket.packet.app.GTP.msg_type_str}</p>
              <p><strong>TEID:</strong> {selectedPacket.packet.app.GTP.teid}</p>

              {/* IE List */}
              <div className="mt-3">
                <strong>Information Elements (IEs):</strong>
                <ul style={{ marginLeft: "20px" }}>
                  {selectedPacket.packet.app.GTP.ies.map((ie, index) => (
                    <li key={index}>
                      <strong>{ie.name}</strong> → {JSON.stringify(ie.value)}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

        </div>
      </div>
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
    // <div style={{ marginTop: 16 }}>
    //   <h3>Parse Result (raw JSON)</h3>
    //   <div style={{
    //     background: "#0b1220",
    //     color: "#dff1c8",
    //     padding: 12,
    //     borderRadius: 6,
    //     maxHeight: "40vh",
    //     overflow: "auto",
    //     fontFamily: "monospace",
    //     fontSize: 13
    //   }}>
    //     <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
    //       {JSON.stringify(result, null, 2)}
    //     </pre>
    //   </div>
    // </div>
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

      console.log("print out json: ======>", json);
      setCurrentFile(json.file)
      console.log("print out currentFile:", currentFile);

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
        <h1 className="mb-3">pcap → GTP / PFCP Parser (frontend)</h1>

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

          {/* <button onClick={upload} disabled={loading || !file} style={{ padding: "6px 12px" }}> */}
            {loading ? "Parsing..." : "Upload & Parse"}
          </button>
          {/* <button
          onClick={() => { setFile(null); setResult(null); }}
          style={{ marginLeft: 8 }}> */}
          <button
          variant="secondary" 
              className="btn btn-secondary " 
              onClick={() => { setFile(null); setResult(null); }} >
            Reset
          </button>
        </div>

      {result?.packets && (
          // <div className="alert alert-info mt-3">
          //   Selected <strong>{file.name}</strong> ({file.size} bytes)
          // </div>
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
          // ( <p>No packet selected.</p>)
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
