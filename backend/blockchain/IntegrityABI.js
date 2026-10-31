module.exports = [
  "function anchorIntegrity(bytes32 fileId, uint64 version, bytes32 commitment, uint8 recordType)",
  "function getLatestIntegrity(bytes32 fileId) view returns (tuple(bytes32 commitment, uint64 version, uint8 recordType, uint64 anchoredAt, address signer))",
  "function getHistoricalIntegrity(bytes32 fileId, uint64 version) view returns (tuple(bytes32 commitment, uint64 version, uint8 recordType, uint64 anchoredAt, address signer))",
  "function latestVersion(bytes32 fileId) view returns (uint64)",
  "function authorizedSigners(address) view returns (bool)",
  "function owner() view returns (address)"
];