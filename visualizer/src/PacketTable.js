import React, { useState, useMemo } from "react";
import { Modal, Button } from "react-bootstrap";
import Layer3Header from "./components/headers/Layer3Header";
import Layer4Header from "./components/headers/Layer4Header";
import GtpHeader from "./components/headers/gtp/GtpHeader";
import "./App.css";
import "./Table.css";

// ----------------------------------------------------------------------
// 1. 유틸리티 함수 & 커스텀 훅
// ----------------------------------------------------------------------
const isValidPort = (port) => {
  const n = Number(port);
  return Number.isInteger(n) && n > 0 && n < 65535;
};
const isValidIPv4 = (ip) => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
const isValidIPv6 = (ip) => ip.includes(":");

/** 필터링 로직 전용 훅 */
const usePacketFilters = (packets, filters) => {
  return useMemo(() => {
    if (!packets) return [];
    return packets.filter((pkt) => {
      // TCP Filter
      if (filters.tcp.enabled) {
        if (pkt.l4_type !== "TCP") return false;
        if (filters.tcp.port && isValidPort(filters.tcp.port)) {
          const n = Number(filters.tcp.port);
          if (pkt.src_port !== n && pkt.dst_port !== n) return false;
        }
      }
      // UDP Filter
      if (filters.udp.enabled) {
        if (pkt.l4_type !== "UDP") return false;
        if (filters.udp.port && isValidPort(filters.udp.port)) {
          const n = Number(filters.udp.port);
          if (pkt.src_port !== n && pkt.dst_port !== n) return false;
        }
      }
      // IPv4 Filter
      if (filters.ipv4.enabled && isValidIPv4(filters.ipv4.addr)) {
        if (pkt.src_ip !== filters.ipv4.addr && pkt.dst_ip !== filters.ipv4.addr) return false;
      }
      // IPv6 Filter
      if (filters.ipv6.enabled && isValidIPv6(filters.ipv6.addr)) {
        if (pkt.src_ip !== filters.ipv6.addr && pkt.dst_ip !== filters.ipv6.addr) return false;
      }
      return true;
    });
  }, [packets, filters]);
};

// ----------------------------------------------------------------------
// 2. 내부 서브 컴포넌트
// ----------------------------------------------------------------------

const FilterInputGroup = ({ label, type, config, onChange }) => (
  <div className="d-flex align-items-center gap-2 mb-2">
    <input
      type="checkbox"
      className="form-check-input"
      checked={config.enabled}
      onChange={(e) => onChange(type, "enabled", e.target.checked)}
    />
    <span style={{ minWidth: "45px", fontSize: "14px fw-bold" }}>{label}</span>
    <input
      type="text"
      className="form-control form-control-sm"
      style={{ width: label.includes("IPv") ? "220px" : "120px" }}
      placeholder={label.includes("IPv") ? (label === "IPv4" ? "10.0.0.1" : "2001:db8::1") : "port"}
      disabled={!config.enabled}
      value={config.addr || config.port || ""}
      onChange={(e) => onChange(type, label.includes("IPv") ? "addr" : "port", e.target.value)}
    />
  </div>
);

const PacketRow = ({ pkt, onSelect, onCallFlow }) => {
  const isCreateSession = pkt.description?.includes("Create Session Request");

  return (
    <div
      className={`packet-item proto-${pkt.protocol.toLowerCase()} d-flex align-items-center p-2 mb-2 border rounded shadow-sm`}
      onClick={() => onSelect(pkt.id)}
      style={{ cursor: "pointer" }}
    >
      <div className="packet-side d-flex flex-column align-items-center px-3 border-end">
        <small className="text-muted fw-bold">#{pkt.id}</small>
        <span className="badge bg-primary text-uppercase" style={{ fontSize: "10px" }}>{pkt.protocol}</span>
      </div>

      <div className="packet-main flex-grow-1 px-3">
        <div className="d-flex align-items-center gap-3 justify-content-center mb-1">
          <span className="fw-bold font-monospace">{pkt.src_ip}</span>
          <i className="bi bi-chevron-right text-primary"></i>
          <span className="fw-bold font-monospace">{pkt.dst_ip}</span>
        </div>
        <div className="d-flex justify-content-center gap-2 small border-top pt-1">
          <span className="text-muted fw-bold">{pkt.length} bytes</span>
          <span className="text-secondary">|</span>
          <span className="text-dark truncate-text">{pkt.description}</span>
        </div>
      </div>

      <div className="packet-action px-2">
        {isCreateSession && (
          <button
            className="btn btn-sm btn-outline-info d-flex align-items-center gap-1"
            onClick={(e) => {
              e.stopPropagation();
              onCallFlow(pkt.id);
            }}
            title="View Sequence Diagram"
          >
            <span style={{ fontSize: "12px" }}>Flow</span>
            <i className="bi bi-arrow-left-right"></i>
          </button>
        )}
      </div>
    </div>
  );
};

// ----------------------------------------------------------------------
// 3. 메인 컴포넌트
// ----------------------------------------------------------------------

function PacketTable({ packets, fileId, onCallFlow }) {
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [filters, setFilters] = useState({
    tcp: { enabled: false, port: "" },
    udp: { enabled: false, port: "" },
    ipv4: { enabled: false, addr: "" },
    ipv6: { enabled: false, addr: "" },
  });

  const filteredPackets = usePacketFilters(packets, filters);

  const handleClose = () => {
    setShowModal(false);
    setSelectedPacket(null);
  };

  const handleFilterChange = (proto, field, value) => {
    setFilters((prev) => ({
      ...prev,
      [proto]: { ...prev[proto], [field]: value },
    }));
  };

  const fetchPacketDetail = async (id) => {
    if (!fileId) return alert("No file selected!");
    try {
      const res = await fetch(`/api/packet_detail?file_id=${fileId}&id=${encodeURIComponent(id)}`);
      if (!res.ok) throw new Error(`Server Error: ${res.status}`);
      const data = await res.json();
      setSelectedPacket(data);
      setShowModal(true);
    } catch (err) {
      console.error(err);
      alert("Failed to fetch packet detail");
    }
  };

  return (
    <div className="container-fluid mt-4 px-4">
      {/* Filter Section */}
      <div className="card shadow-sm border-0 mb-4 bg-light">
        <div className="card-body">
          <h6 className="fw-bold text-uppercase text-muted mb-3">Packet Filters</h6>
          <div className="row">
            <div className="col-md-6 border-end">
              <FilterInputGroup label="IPv4" type="ipv4" config={filters.ipv4} onChange={handleFilterChange} />
              <FilterInputGroup label="IPv6" type="ipv6" config={filters.ipv6} onChange={handleFilterChange} />
            </div>
            <div className="col-md-6">
              <FilterInputGroup label="TCP" type="tcp" config={filters.tcp} onChange={handleFilterChange} />
              <FilterInputGroup label="UDP" type="udp" config={filters.udp} onChange={handleFilterChange} />
            </div>
          </div>
        </div>
      </div>

      {/* Packet List */}
      <div className="packet-container" style={{ maxHeight: "70vh", overflowY: "auto" }}>
        {filteredPackets.length > 0 ? (
          filteredPackets.map((pkt) => (
            <PacketRow key={pkt.id} pkt={pkt} onSelect={fetchPacketDetail} onCallFlow={onCallFlow} />
          ))
        ) : (
          <div className="text-center p-5 bg-white border rounded shadow-sm text-muted">
            <i className="bi bi-search fs-2 mb-2 d-block"></i>
            No packets matched your filters.
          </div>
        )}
      </div>

      {/* Detail Modal */}
      <Modal show={showModal} onHide={handleClose} centered size="lg" dialogClassName="my-wide-modal">
        <Modal.Header closeButton className="bg-light">
          <Modal.Title className="fs-6 fw-bold">
            Packet Details - #{selectedPacket?.id}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body style={{ backgroundColor: "#f8f9fa" }}>
          {selectedPacket && (
            <div className="detail-view font-monospace" style={{ fontSize: "13px" }}>
              {selectedPacket.packet.l3.map((l3, idx) => (
                <Layer3Header key={idx} l3={l3} idx={idx} />
              ))}
              <Layer4Header l4={selectedPacket.packet.l4} />
              {selectedPacket.packet.app?.GTP && <GtpHeader gtp={selectedPacket.packet.app.GTP} />}
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" size="sm" onClick={handleClose}>Close</Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}

export default PacketTable;