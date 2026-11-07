module.exports = [
  "function anchorIntegrity(bytes32 fileId, uint64 version, bytes32 commitment, uint8 recordType)",
  "function getLatestIntegrity(bytes32 fileId) view returns (tuple(bytes32 commitment, uint64 version, uint8 recordType, uint64 anchoredAt, address signer))",
  "function getHistoricalIntegrity(bytes32 fileId, uint64 version) view returns (tuple(bytes32 commitment, uint64 version, uint8 recordType, uint64 anchoredAt, address signer))",
  "function latestVersion(bytes32 fileId) view returns (uint64)",
  "function owner() view returns (address)",
  "function anchorAuditEvent(bytes32 eventId, bytes32 commitment)",
  "function getAuditEvent(bytes32 eventId) view returns (tuple(bytes32 commitment, uint64 anchoredAt, address signer, bool exists))",
  "function anchorAuditBatch(bytes32 batchId, bytes32 merkleRoot, uint32 leafCount)",
  "function getAuditBatch(bytes32 batchId) view returns (tuple(bytes32 merkleRoot, uint64 anchoredAt, address signer, uint32 leafCount, bool exists))",
  "function verifyAuditProof(bytes32 batchId, bytes32 commitment, uint256 leafIndex, bytes32[] proof) view returns (bool)",
  "function authorizedSigners(address) view returns (bool)",
  "event AuditEventAnchored(bytes32 indexed eventId, bytes32 commitment, address signer, uint256 timestamp)",
  "event AuditBatchAnchored(bytes32 indexed batchId, bytes32 merkleRoot, uint32 leafCount, address signer, uint256 timestamp)"
];