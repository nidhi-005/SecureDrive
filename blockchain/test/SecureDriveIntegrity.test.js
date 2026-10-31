
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SecureDriveIntegrity", function () {
  let contract;
  let owner;
  let signer;
  let outsider;

  let fileId;
  let commitment1;
  let commitment2;

  beforeEach(async function () {
    [owner, signer, outsider] = await ethers.getSigners();

    const Factory = await ethers.getContractFactory(
      "SecureDriveIntegrity"
    );

    contract = await Factory.deploy(signer.address);
    await contract.waitForDeployment();

    fileId = ethers.keccak256(
      ethers.toUtf8Bytes("opaque-file-001")
    );

    commitment1 = ethers.sha256(
      ethers.toUtf8Bytes("integrity-record-v1")
    );

    commitment2 = ethers.sha256(
      ethers.toUtf8Bytes("integrity-record-v2")
    );
  });

  describe("Deployment and authorization", function () {
    it("should assign the deployer as owner", async function () {
      expect(await contract.owner()).to.equal(owner.address);
    });

    it("should authorize the initial signer", async function () {
      expect(
        await contract.authorizedSigners(signer.address)
      ).to.equal(true);
    });

    it("should reject unauthorized integrity submissions", async function () {
      await expect(
        contract.connect(outsider).anchorIntegrity(
          fileId,
          1,
          commitment1,
          1
        )
      ).to.be.revertedWith("Not authorized signer");
    });

    it("should allow owner to authorize another signer", async function () {
      await contract.setAuthorizedSigner(
        outsider.address,
        true
      );

      expect(
        await contract.authorizedSigners(outsider.address)
      ).to.equal(true);
    });

    it("should allow owner to revoke a signer", async function () {
      await contract.setAuthorizedSigner(
        signer.address,
        false
      );

      expect(
        await contract.authorizedSigners(signer.address)
      ).to.equal(false);
    });

    it("should reject signer management by non-owner", async function () {
      await expect(
        contract.connect(outsider).setAuthorizedSigner(
          outsider.address,
          true
        )
      ).to.be.revertedWith("Not contract owner");
    });
  });

  describe("Integrity commitments", function () {
    it("should anchor the first integrity commitment", async function () {
      await contract.connect(signer).anchorIntegrity(
        fileId,
        1,
        commitment1,
        1
      );

      expect(
        await contract.latestVersion(fileId)
      ).to.equal(1);

      const record = await contract.getLatestIntegrity(fileId);

      expect(record.commitment).to.equal(commitment1);
      expect(record.version).to.equal(1);
      expect(record.recordType).to.equal(1);
      expect(record.signer).to.equal(signer.address);
    });

    it("should support sequential versions", async function () {
      await contract.connect(signer).anchorIntegrity(
        fileId,
        1,
        commitment1,
        1
      );

      await contract.connect(signer).anchorIntegrity(
        fileId,
        2,
        commitment2,
        1
      );

      expect(
        await contract.latestVersion(fileId)
      ).to.equal(2);
    });

    it("should reject skipped versions", async function () {
      await expect(
        contract.connect(signer).anchorIntegrity(
          fileId,
          2,
          commitment2,
          1
        )
      ).to.be.revertedWith("Invalid version sequence");
    });

    it("should reject duplicate versions", async function () {
      await contract.connect(signer).anchorIntegrity(
        fileId,
        1,
        commitment1,
        1
      );

      await expect(
        contract.connect(signer).anchorIntegrity(
          fileId,
          1,
          commitment2,
          1
        )
      ).to.be.revertedWith("Invalid version sequence");
    });

    it("should reject zero file IDs", async function () {
      await expect(
        contract.connect(signer).anchorIntegrity(
          ethers.ZeroHash,
          1,
          commitment1,
          1
        )
      ).to.be.revertedWith("Invalid file ID");
    });

    it("should reject zero commitments", async function () {
      await expect(
        contract.connect(signer).anchorIntegrity(
          fileId,
          1,
          ethers.ZeroHash,
          1
        )
      ).to.be.revertedWith("Invalid commitment");
    });

    it("should reject invalid record types", async function () {
      await expect(
        contract.connect(signer).anchorIntegrity(
          fileId,
          1,
          commitment1,
          3
        )
      ).to.be.revertedWith("Invalid record type");
    });

    it("should preserve historical commitments", async function () {
      await contract.connect(signer).anchorIntegrity(
        fileId,
        1,
        commitment1,
        1
      );

      await contract.connect(signer).anchorIntegrity(
        fileId,
        2,
        commitment2,
        1
      );

      const oldRecord =
        await contract.getHistoricalIntegrity(fileId, 1);

      const latestRecord =
        await contract.getLatestIntegrity(fileId);

      expect(oldRecord.commitment).to.equal(commitment1);
      expect(latestRecord.commitment).to.equal(commitment2);
    });

    it("should reject requests for nonexistent history", async function () {
      await expect(
        contract.getHistoricalIntegrity(fileId, 1)
      ).to.be.revertedWith("Invalid historical version");
    });
  });

  describe("Deletion tombstones", function () {
    it("should preserve history and mark a file as deleted", async function () {
      await contract.connect(signer).anchorIntegrity(
        fileId,
        1,
        commitment1,
        1
      );

      await contract.connect(signer).anchorIntegrity(
        fileId,
        2,
        commitment2,
        2
      );

      const latest = await contract.getLatestIntegrity(fileId);
      const historical = await contract.getHistoricalIntegrity(
        fileId,
        1
      );

      expect(latest.recordType).to.equal(2);
      expect(historical.commitment).to.equal(commitment1);
    });

    it("should reject new commitments after deletion", async function () {
      await contract.connect(signer).anchorIntegrity(
        fileId,
        1,
        commitment1,
        1
      );

      await contract.connect(signer).anchorIntegrity(
        fileId,
        2,
        commitment2,
        2
      );

      await expect(
        contract.connect(signer).anchorIntegrity(
          fileId,
          3,
          commitment1,
          1
        )
      ).to.be.revertedWith("File already deleted");
    });
  });

  describe("Audit commitments", function () {
    const eventId = ethers.keccak256(
      ethers.toUtf8Bytes("opaque-audit-event-001")
    );

    const auditDigest = ethers.sha256(
      ethers.toUtf8Bytes("canonical-audit-event")
    );

    it("should anchor an audit event", async function () {
      await contract.connect(signer).anchorAuditEvent(
        eventId,
        auditDigest
      );

      const record = await contract.getAuditEvent(eventId);

      expect(record.commitment).to.equal(auditDigest);
      expect(record.signer).to.equal(signer.address);
      expect(record.exists).to.equal(true);
    });

    it("should reject duplicate audit events", async function () {
      await contract.connect(signer).anchorAuditEvent(
        eventId,
        auditDigest
      );

      await expect(
        contract.connect(signer).anchorAuditEvent(
          eventId,
          commitment1
        )
      ).to.be.revertedWith("Audit event already anchored");
    });

    it("should reject unauthorized audit submissions", async function () {
      await expect(
        contract.connect(outsider).anchorAuditEvent(
          eventId,
          auditDigest
        )
      ).to.be.revertedWith("Not authorized signer");
    });

    it("should reject nonexistent audit records", async function () {
      await expect(
        contract.getAuditEvent(ethers.ZeroHash)
      ).to.be.revertedWith("Audit event not found");
    });
  });
});
