const {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
  GetObjectCommand
} = require('@aws-sdk/client-s3');

const { randomUUID } = require('crypto');
const RecoveryStore = require('./recoveryStore');

const BUCKET_NAME = process.env.AWS_RECOVERY_BUCKET_NAME;

const s3 = new S3Client({
  region: process.env.AWS_REGION
});

function validateId(value, name) {
  if (!value || !/^[a-zA-Z0-9_-]+$/.test(String(value))) {
    throw new Error(`Invalid ${name}`);
  }
}

class S3RecoveryStore extends RecoveryStore {
  async append(record) {
    if (!BUCKET_NAME) {
      throw new Error('AWS_RECOVERY_BUCKET_NAME is not configured');
    }

    validateId(record.userId, 'userId');

    let key;

    if (record.recordType === 'MASTER_KEY') {
      key = `users/${record.userId}/master-key/`;
    } else if (record.recordType === 'FILE_CEK') {
      validateId(record.fileId, 'fileId');
      key = `users/${record.userId}/files/${record.fileId}/`;
    } else {
      throw new Error('Unsupported recovery record type');
    }

    // Unique object names prevent accidental replacement of old records.
    key += `v${record.version}-${Date.now()}-${randomUUID()}.json`;

    await s3.send(new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      Body: JSON.stringify(record),
      ContentType: 'application/json'
    }));
  }

  async readRecords(prefix) {
    if (!BUCKET_NAME) {
      throw new Error('AWS_RECOVERY_BUCKET_NAME is not configured');
    }

    const records = [];
    let continuationToken;

    do {
      const response = await s3.send(new ListObjectsV2Command({
        Bucket: BUCKET_NAME,
        Prefix: prefix,
        ContinuationToken: continuationToken
      }));

      for (const object of response.Contents || []) {
        if (!object.Key.endsWith('.json')) continue;

        const result = await s3.send(new GetObjectCommand({
          Bucket: BUCKET_NAME,
          Key: object.Key
        }));

        const body = await result.Body.transformToString();
        records.push(JSON.parse(body));
      }

      continuationToken = response.IsTruncated
        ? response.NextContinuationToken
        : undefined;
    } while (continuationToken);

    return records.sort((a, b) =>
      b.version - a.version ||
      new Date(b.createdAt) - new Date(a.createdAt)
    );
  }

  async getMasterKeyHistory(userId) {
    validateId(userId, 'userId');

    const records = await this.readRecords(
      `users/${userId}/master-key/`
    );

    return records.filter(record =>
      record.recordType === 'MASTER_KEY' &&
      record.userId === String(userId)
    );
  }

  async getFileKeyHistory(userId, fileId) {
    validateId(userId, 'userId');
    validateId(fileId, 'fileId');

    const records = await this.readRecords(
      `users/${userId}/files/${fileId}/`
    );

    return records.filter(record =>
      record.recordType === 'FILE_CEK' &&
      record.userId === String(userId) &&
      record.fileId === String(fileId)
    );
  }

}

module.exports = new S3RecoveryStore();
