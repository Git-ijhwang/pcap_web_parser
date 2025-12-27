function CallFlowView({ data }) {
  if (!data) return null;

  return (
    <div className="callflow-container">
      <CallFlowGraph data={data} />
    </div>
  );
}