const fs = require('fs/promises');
const path = require('path');
const RecoveryStore = require('./recoveryStore');

const RECOVERY_DIR = path.join(__dirname, '..', 'recovery-data');
const LEDGER_PATH = path.join(RECOVERY_DIR, 'recovery-ledger.jsonl');

class LocalRecoveryStore extends RecoveryStore {
  async ensureStorage() {
    await fs.mkdir(RECOVERY_DIR, { recursive: true });
  }

  async append(record) {
    await this.ensureStorage();

    const line = JSON.stringify(record) + '\n';

    // appendFile is deliberately used instead of rewriting the ledger.
    await fs.appendFile(LEDGER_PATH, line, 'utf8');
  }

  async readAll() {
    await this.ensureStorage();

    try {
      const contents = await fs.readFile(LEDGER_PATH, 'utf8');

      if (!contents.trim()) {
        return [];
      }

      return contents
        .trim()
        .split('\n')
        .map(line => JSON.parse(line));
    } catch (error) {
      if (error.code === 'ENOENT') {
        return [];
      }

      throw error;
    }
  }

  async getMasterKeyHistory(userId) {
    const records = await this.readAll();

    return records
      .filter(record =>
        record.recordType === 'MASTER_KEY' &&
        record.userId === String(userId)
      )
      .sort((a, b) => b.version - a.version);
  }

  async getFileKeyHistory(userId, fileId) {
    const records = await this.readAll();

    return records
      .filter(record =>
        record.recordType === 'FILE_CEK' &&
        record.userId === String(userId) &&
        record.fileId === String(fileId)
      )
      .sort((a, b) => b.version - a.version);
  }
}

module.exports = new LocalRecoveryStore();