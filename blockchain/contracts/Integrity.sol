// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * SecureDrive Integrity Contract
 *
 * Maintains:
 * 1. Append-only file integrity commitments.
 * 2. Sequential integrity versions.
 * 3. Permanent historical commitment lookup.
 * 4. File deletion tombstones.
 * 5. Append-only security audit commitments.
 *
 * No file contents, keys, filenames, or personal information
 * are stored on-chain.
 */
contract SecureDriveIntegrity {
    // --------------------------------------------------
    // ACCESS CONTROL
    // --------------------------------------------------

    address public owner;

    mapping(address => bool) public authorizedSigners;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner");
        _;
    }

    modifier onlySigner() {
        require(authorizedSigners[msg.sender], "Not authorized signer");
        _;
    }

    // --------------------------------------------------
    // INTEGRITY RECORDS
    // --------------------------------------------------

    // Record types:
    // 1 = FILE_INTEGRITY
    // 2 = FILE_DELETION_TOMBSTONE

    struct IntegrityRecord {
        bytes32 commitment;
        uint64 version;
        uint8 recordType;
        uint64 anchoredAt;
        address signer;
    }

    // fileId => version => historical record
    mapping(bytes32 => mapping(uint64 => IntegrityRecord))
        private integrityHistory;

    // Independently maintained latest version
    mapping(bytes32 => uint64) public latestVersion;

    // --------------------------------------------------
    // AUDIT RECORDS
    // --------------------------------------------------

    struct AuditRecord {
        bytes32 commitment;
        uint64 anchoredAt;
        address signer;
        bool exists;
    }

    struct AuditBatchRecord {
        bytes32 merkleRoot;
        uint64 anchoredAt;
        address signer;
        uint32 leafCount;
        bool exists;
    }

    mapping(bytes32 => AuditBatchRecord) private auditBatches;

    mapping(bytes32 => AuditRecord) private auditHistory;

    // --------------------------------------------------
    // EVENTS
    // --------------------------------------------------

    event AuditBatchAnchored(
        bytes32 indexed batchId,
        bytes32 merkleRoot,
        uint32 leafCount,
        address signer,
        uint256 timestamp
    );

    event IntegrityAnchored(
        bytes32 indexed fileId,
        uint64 indexed version,
        bytes32 commitment,
        uint8 recordType,
        address signer,
        uint256 timestamp
    );

    event AuditEventAnchored(
        bytes32 indexed eventId,
        bytes32 commitment,
        address signer,
        uint256 timestamp
    );

    event SignerUpdated(address indexed signer, bool authorized);

    // --------------------------------------------------
    // CONSTRUCTOR
    // --------------------------------------------------

    constructor(address initialSigner) {
        require(initialSigner != address(0), "Invalid initial signer");

        owner = msg.sender;
        authorizedSigners[initialSigner] = true;

        emit SignerUpdated(initialSigner, true);
    }

    // --------------------------------------------------
    // SIGNER MANAGEMENT
    // --------------------------------------------------

    function setAuthorizedSigner(
        address signer,
        bool authorized
    ) external onlyOwner {
        require(signer != address(0), "Invalid signer address");

        authorizedSigners[signer] = authorized;

        emit SignerUpdated(signer, authorized);
    }

    // --------------------------------------------------
    // FILE INTEGRITY COMMITMENT
    // --------------------------------------------------

    function anchorIntegrity(
        bytes32 fileId,
        uint64 version,
        bytes32 commitment,
        uint8 recordType
    ) external onlySigner {
        require(fileId != bytes32(0), "Invalid file ID");

        require(commitment != bytes32(0), "Invalid commitment");

        require(recordType == 1 || recordType == 2, "Invalid record type");

        uint64 currentVersion = latestVersion[fileId];

        require(
            recordType != 2 || currentVersion > 0,
            "Cannot delete unknown file"
        );

        // A deleted file cannot be silently reactivated.
        require(
            currentVersion == 0 ||
                integrityHistory[fileId][currentVersion].recordType != 2,
            "File already deleted"
        );

        // Strict sequential versioning.
        require(version == currentVersion + 1, "Invalid version sequence");

        IntegrityRecord memory record = IntegrityRecord({
            commitment: commitment,
            version: version,
            recordType: recordType,
            anchoredAt: uint64(block.timestamp),
            signer: msg.sender
        });

        integrityHistory[fileId][version] = record;

        latestVersion[fileId] = version;

        emit IntegrityAnchored(
            fileId,
            version,
            commitment,
            recordType,
            msg.sender,
            block.timestamp
        );
    }

    // --------------------------------------------------
    // LATEST INTEGRITY LOOKUP
    // --------------------------------------------------

    function getLatestIntegrity(
        bytes32 fileId
    ) external view returns (IntegrityRecord memory) {
        uint64 version = latestVersion[fileId];

        require(version != 0, "No integrity record");

        return integrityHistory[fileId][version];
    }

    // --------------------------------------------------
    // HISTORICAL INTEGRITY LOOKUP
    // --------------------------------------------------

    function getHistoricalIntegrity(
        bytes32 fileId,
        uint64 version
    ) external view returns (IntegrityRecord memory) {
        require(
            version != 0 && version <= latestVersion[fileId],
            "Invalid historical version"
        );

        return integrityHistory[fileId][version];
    }

    // --------------------------------------------------
    // AUDIT EVENT COMMITMENT
    // --------------------------------------------------

    function anchorAuditEvent(
        bytes32 eventId,
        bytes32 commitment
    ) external onlySigner {
        require(eventId != bytes32(0), "Invalid event ID");

        require(commitment != bytes32(0), "Invalid commitment");

        require(!auditHistory[eventId].exists, "Audit event already anchored");

        auditHistory[eventId] = AuditRecord({
            commitment: commitment,
            anchoredAt: uint64(block.timestamp),
            signer: msg.sender,
            exists: true
        });

        emit AuditEventAnchored(
            eventId,
            commitment,
            msg.sender,
            block.timestamp
        );
    }

    // --------------------------------------------------
    // AUDIT LOOKUP
    // --------------------------------------------------

    function getAuditEvent(
        bytes32 eventId
    ) external view returns (AuditRecord memory) {
        require(auditHistory[eventId].exists, "Audit event not found");

        return auditHistory[eventId];
    }

    // --------------------------------------------------
    // MERKLE AUDIT BATCH ANCHORING
    // --------------------------------------------------

    function anchorAuditBatch(
        bytes32 batchId,
        bytes32 merkleRoot,
        uint32 leafCount
    ) external onlySigner {
        require(batchId != bytes32(0), "Invalid batch ID");
        require(merkleRoot != bytes32(0), "Invalid Merkle root");
        require(leafCount > 0, "Empty audit batch");
        require(!auditBatches[batchId].exists, "Batch already anchored");

        auditBatches[batchId] = AuditBatchRecord({
            merkleRoot: merkleRoot,
            anchoredAt: uint64(block.timestamp),
            signer: msg.sender,
            leafCount: leafCount,
            exists: true
        });

        emit AuditBatchAnchored(
            batchId,
            merkleRoot,
            leafCount,
            msg.sender,
            block.timestamp
        );
    }

    function getAuditBatch(
        bytes32 batchId
    ) external view returns (AuditBatchRecord memory) {
        require(auditBatches[batchId].exists, "Audit batch not found");
        return auditBatches[batchId];
    }

    // --------------------------------------------------
    // MERKLE PROOF VERIFICATION
    // --------------------------------------------------

    function verifyAuditProof(
        bytes32 batchId,
        bytes32 commitment,
        uint256 leafIndex,
        bytes32[] calldata proof
    ) external view returns (bool) {
        AuditBatchRecord memory batch = auditBatches[batchId];

        require(batch.exists, "Audit batch not found");
        require(leafIndex < batch.leafCount, "Invalid leaf index");

        // Must match merkleService.js hashLeaf():
        // SHA256(0x00 || commitment)
        bytes32 computed = sha256(abi.encodePacked(bytes1(0x00), commitment));

        uint256 position = leafIndex;

        for (uint256 i = 0; i < proof.length; i++) {
            // Must match merkleService.js hashPair():
            // SHA256(0x01 || left || right)
            if (position % 2 == 0) {
                computed = sha256(
                    abi.encodePacked(bytes1(0x01), computed, proof[i])
                );
            } else {
                computed = sha256(
                    abi.encodePacked(bytes1(0x01), proof[i], computed)
                );
            }

            position /= 2;
        }

        return computed == batch.merkleRoot;
    }
}
