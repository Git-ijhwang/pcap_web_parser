import React, { useState, useRef } from "react";
import {Modal, Button} from "react-bootstrap";
import "./App.css";

import PacketTable from "./PacketTable"


function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [currentFile, setCurrentFile] = useState(null);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [collapsed, setCollapsed] = useState(null);
  // const [result, setResult] = useState(null);
  const [fileId, setFileId] = useState(null);


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
      setResult(json.packets);
      // setCurrentFile(json.file)
      setFileId(json.file_id);

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
              fileId={fileId}
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

      </div>
    </div>
  );
}

export default App;
