module.exports = [
  "function anchorIntegrity(bytes32 fileId, uint64 version, bytes32 commitment, uint8 recordType)",
  "function getLatestIntegrity(bytes32 fileId) view returns (tuple(bytes32 commitment, uint64 version, uint8 recordType, uint64 anchoredAt, address signer))",
  "function getHistoricalIntegrity(bytes32 fileId, uint64 version) view returns (tuple(bytes32 commitment, uint64 version, uint8 recordType, uint64 anchoredAt, address signer))",
  "function latestVersion(bytes32 fileId) view returns (uint64)",
  "function owner() view returns (address)",
  "function anchorAuditEvent(bytes32 eventId, bytes32 commitment)",
  "function getAuditEvent(bytes32 eventId) view returns (tuple(bytes32 commitment, uint64 anchoredAt, address signer, bool exists))",
  "event AuditEventAnchored(bytes32 indexed eventId, bytes32 commitment, address signer, uint256 timestamp)",
  "function authorizedSigners(address) view returns (bool)"
];