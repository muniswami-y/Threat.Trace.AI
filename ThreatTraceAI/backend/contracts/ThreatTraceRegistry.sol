// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatTraceRegistry
 * @dev Immutable chain-of-custody registry for AI threat attribution,
 *      IOC Merkle tree anchoring, and verifiable forensic provenance.
 */
contract ThreatTraceRegistry {
    address public immutable forensicAuthority;

    struct ForensicRecord {
        bytes32 merkleRoot;        // Merkle Root combining all IOCs, attack paths, and rubric
        bytes32 canonicalHash;     // Deterministic SHA-256 case digest
        bytes32 clientDigest;      // WebCrypto ingestion hash from client
        uint8 riskScore;           // AI Explainable Risk Score (0 - 100)
        string ipfsCid;            // Off-chain encrypted evidence vault pointer (IPFS/Arweave)
        uint256 timestamp;         // Block timestamp of anchoring
        address investigator;      // Signing investigator address
    }

    // Mapping: caseId => ForensicRecord
    mapping(string => ForensicRecord) public records;

    // Mapping: caseId => bool existence check
    mapping(string => bool) public isCaseAnchored;

    event CaseAnchored(
        string indexed caseId,
        bytes32 indexed merkleRoot,
        bytes32 canonicalHash,
        uint8 riskScore,
        string ipfsCid,
        uint256 timestamp,
        address indexed investigator
    );

    event EvidenceAudited(
        string indexed caseId,
        bool verified,
        uint256 auditedAt,
        address indexed auditor
    );

    modifier onlyAuthority() {
        require(msg.sender == forensicAuthority, "Only ThreatTrace Forensic Authority can anchor records");
        _;
    }

    constructor() {
        forensicAuthority = msg.sender;
    }

    /**
     * @notice Anchors a finalized forensic case to the blockchain.
     */
    function anchorForensicCase(
        string calldata caseId,
        bytes32 merkleRoot,
        bytes32 canonicalHash,
        bytes32 clientDigest,
        uint8 riskScore,
        string calldata ipfsCid
    ) external onlyAuthority {
        require(!isCaseAnchored[caseId], "Case ID already registered in immutable ledger");
        require(riskScore <= 100, "Risk score must be between 0 and 100");

        records[caseId] = ForensicRecord({
            merkleRoot: merkleRoot,
            canonicalHash: canonicalHash,
            clientDigest: clientDigest,
            riskScore: riskScore,
            ipfsCid: ipfsCid,
            timestamp: block.timestamp,
            investigator: msg.sender
        });

        isCaseAnchored[caseId] = true;

        emit CaseAnchored(
            caseId,
            merkleRoot,
            canonicalHash,
            riskScore,
            ipfsCid,
            block.timestamp,
            msg.sender
        );
    }

    /**
     * @notice Verifies whether a given evidence hash and Merkle root match the immutable record.
     */
    function verifyForensicCase(
        string calldata caseId,
        bytes32 targetMerkleRoot,
        bytes32 targetCanonicalHash
    ) external returns (bool isValid, uint256 anchoredAt, address investigator) {
        require(isCaseAnchored[caseId], "Case not found on blockchain");

        ForensicRecord memory rec = records[caseId];
        isValid = (rec.merkleRoot == targetMerkleRoot && rec.canonicalHash == targetCanonicalHash);

        emit EvidenceAudited(caseId, isValid, block.timestamp, msg.sender);

        return (isValid, rec.timestamp, rec.investigator);
    }

    /**
     * @notice Returns complete record details for judicial audit.
     */
    function getCaseRecord(string calldata caseId) external view returns (ForensicRecord memory) {
        require(isCaseAnchored[caseId], "Case not found");
        return records[caseId];
    }
}
