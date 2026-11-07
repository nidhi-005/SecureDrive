const mongoose = require('mongoose');
const crypto = require('crypto');

const auditBatchSchema = new mongoose.Schema({
    batchId: {
        type: String,
        required: true,
        unique: true,
        immutable: true,
        default: () => '0x' + crypto.randomBytes(32).toString('hex')
    },

    leaseId: {
        type: String,
        default: null
    },

    leaseUntil: {
        type: Date,
        default: null,
        index: true
    },
    
    status: {
        type: String,
        enum: ['BUILDING', 'PENDING', 'ANCHORED', 'FAILED'],
        default: 'BUILDING',
        index: true
    },

    eventIds: [{
        type: String,
        required: true
    }],

    merkleRoot: {
        type: String,
        required: true
    },

    leafCount: {
        type: Number,
        required: true
    },

    transactionHash: {
        type: String,
        default: null
    },

    blockNumber: {
        type: Number,
        default: null
    },

    createdAt: {
        type: Date,
        default: Date.now
    },

    anchoredAt: {
        type: Date,
        default: null
    },

    attempts: {
        type: Number,
        default: 0
    },

    nextRetryAt: {
        type: Date,
        default: Date.now
    },

    lastError: {
        type: String,
        default: null
    }
}, { timestamps: true });

module.exports = mongoose.model('AuditBatch', auditBatchSchema);